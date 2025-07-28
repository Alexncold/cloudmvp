import { Worker, Job } from 'bullmq';
import { Redis } from 'ioredis';
import { logger } from '../utils/logger';
import { PrismaClient } from '@prisma/client';
import { ONVIFService } from '../services/onvif.service';
import { io } from '../app';
import { CameraStatus } from '../../../shared/types/onvif';

// Configuración de Redis
const redis = new Redis({
  host: process.env.REDIS_URL?.split('://')[1]?.split(':')[0] || 'localhost',
  port: parseInt(process.env.REDIS_URL?.split(':')[2] || '6379'),
  password: process.env.REDIS_PASSWORD,
  maxRetriesPerRequest: 3,
  retryStrategy: (times) => {
    const delay = Math.min(times * 1000, 5000);
    return delay;
  },
  reconnectOnError: (err) => {
    logger.error('Redis connection error:', err);
    return true; // Reintentar la conexión
  }
});

// Configuración del worker
const WORKER_CONCURRENCY = parseInt(process.env.HEARTBEAT_CONCURRENCY || '5');
const HEARTBEAT_INTERVAL = parseInt(process.env.HEARTBEAT_INTERVAL || '300000'); // 5 minutos por defecto
const MAX_RETRIES = 3;

// Tipos para el trabajo del worker
interface HeartbeatJobData {
  cameraId?: string; // Opcional: ID de cámara específica para verificación puntual
  forceCheck?: boolean; // Forzar verificación incluso si no es el momento programado
}

/**
 * Clase principal del worker de latido (heartbeat)
 * Se encarga de verificar periódicamente el estado de las cámaras
 */
class HeartbeatWorker {
  private worker: Worker<HeartbeatJobData>;
  private onvifService: ONVIFService;
  private prisma: PrismaClient;
  private isRunning: boolean = false;
  private intervalId?: NodeJS.Timeout;

  constructor() {
    this.onvifService = new ONVIFService();
    this.prisma = new PrismaClient();
    this.initializeWorker();
    this.startScheduledChecks();
  }

  /**
   * Inicializa el worker de BullMQ
   */
  private initializeWorker() {
    this.worker = new Worker<HeartbeatJobData>(
      'camera-heartbeat',
      async (job) => this.processHeartbeatJob(job),
      {
        connection: redis,
        concurrency: WORKER_CONCURRENCY,
        removeOnComplete: { count: 100 },
        removeOnFail: { count: 1000 },
      }
    );

    this.setupWorkerEvents();
  }

  /**
   * Configura los manejadores de eventos del worker
   */
  private setupWorkerEvents() {
    this.worker.on('completed', (job) => {
      logger.info(`Heartbeat job completed for camera ${job.data.cameraId || 'all'}`);
    });

    this.worker.on('failed', (job, error) => {
      logger.error(`Heartbeat job failed for camera ${job?.data.cameraId || 'all'}:`, error);
    });

    this.worker.on('error', (error) => {
      logger.error('Heartbeat worker error:', error);
    });
  }

  /**
   * Inicia las verificaciones programadas
   */
  private startScheduledChecks() {
    if (this.intervalId) {
      clearInterval(this.intervalId);
    }

    this.intervalId = setInterval(() => {
      this.enqueueHeartbeatCheck();
    }, HEARTBEAT_INTERVAL);

    // Ejecutar la primera verificación al inicio
    this.enqueueHeartbeatCheck();
  }

  /**
   * Encola una verificación de latido
   */
  public async enqueueHeartbeatCheck(cameraId?: string, forceCheck: boolean = false) {
    try {
      await this.worker.add('heartbeat-check', { cameraId, forceCheck });
      logger.debug(`Heartbeat check enqueued for camera ${cameraId || 'all'}`);
    } catch (error) {
      logger.error('Error enqueuing heartbeat check:', error);
    }
  }

  /**
   * Procesa un trabajo de verificación de latido
   */
  private async processHeartbeatJob(job: Job<HeartbeatJobData>): Promise<void> {
    const { cameraId, forceCheck } = job.data;
    
    try {
      if (cameraId) {
        // Verificar una cámara específica
        await this.checkCameraStatus(cameraId);
      } else {
        // Verificar todas las cámaras activas
        await this.checkAllCameras(forceCheck);
      }
      
      await job.updateProgress(100);
    } catch (error) {
      logger.error('Error processing heartbeat job:', error);
      throw error;
    }
  }

  /**
   * Verifica el estado de todas las cámaras activas
   */
  private async checkAllCameras(forceCheck: boolean = false): Promise<void> {
    if (this.isRunning && !forceCheck) {
      logger.debug('Heartbeat check already in progress');
      return;
    }

    this.isRunning = true;
    logger.info('Starting heartbeat check for all cameras');

    try {
      // Obtener todas las cámaras activas
      const cameras = await this.prisma.camera.findMany({
        where: {
          status: {
            in: ['active', 'warning', 'offline']
          }
        },
        include: {
          rtspUrls: {
            where: { isActive: true },
            take: 1
          }
        }
      });

      logger.info(`Checking status for ${cameras.length} cameras`);

      // Procesar cámaras en lotes para no sobrecargar el sistema
      const batchSize = 5;
      for (let i = 0; i < cameras.length; i += batchSize) {
        const batch = cameras.slice(i, i + batchSize);
        await Promise.all(
          batch.map(camera => this.checkCameraStatus(camera.id, false))
        );
      }

      logger.info('Completed heartbeat check for all cameras');
    } catch (error) {
      logger.error('Error checking all cameras:', error);
      throw error;
    } finally {
      this.isRunning = false;
    }
  }

  /**
   * Verifica el estado de una cámara específica
   */
  public async checkCameraStatus(cameraId: string, updateLastChecked: boolean = true): Promise<boolean> {
    try {
      // Obtener la cámara de la base de datos
      const camera = await this.prisma.camera.findUnique({
        where: { id: cameraId },
        include: {
          rtspUrls: {
            where: { isActive: true },
            take: 1
          },
          _count: {
            select: { failedHeartbeats: { where: { resolved: false } } }
          }
        }
      });

      if (!camera) {
        logger.warn(`Camera ${cameraId} not found`);
        return false;
      }

      // Obtener la URL del stream RTSP activo (si existe)
      const rtspUrl = camera.rtspUrls[0]?.url;

      // Realizar la verificación de latido
      const result = await this.onvifService.performHeartbeat({
        ipAddress: camera.ipAddress,
        port: camera.port || 80,
        username: camera.username || '',
        password: camera.password || '',
        rtspUrl,
        manufacturer: camera.manufacturer || undefined
      });

      // Determinar el nuevo estado de la cámara
      let newStatus: CameraStatus = 'offline';
      let isOnline = false;

      if (result.isOnline) {
        isOnline = true;
        if (result.onvif && result.rtsp) {
          newStatus = 'active';
        } else if (result.onvif || result.rtsp) {
          newStatus = 'warning';
        } else {
          newStatus = 'offline';
        }
      }

      // Actualizar el estado de la cámara en la base de datos
      const updatedCamera = await this.prisma.camera.update({
        where: { id: camera.id },
        data: {
          isOnline,
          status: newStatus,
          lastSeen: result.lastSeen || new Date(),
          lastChecked: updateLastChecked ? new Date() : undefined,
          uptime: result.uptime,
          failedHeartbeats: {
            create: !isOnline ? {
              reason: !result.ping ? 'No response to ping' :
                     !result.onvif ? 'ONVIF service not responding' :
                     !result.rtsp ? 'RTSP stream not available' : 'Unknown error',
              details: JSON.stringify(result)
            } : undefined
          }
        },
        include: {
          _count: {
            select: { failedHeartbeats: { where: { resolved: false } } }
          }
        }
      });

      // Resolver alertas si la cámara está en línea
      if (isOnline && updatedCamera._count.failedHeartbeats > 0) {
        await this.prisma.failedHeartbeat.updateMany({
          where: { cameraId: camera.id, resolved: false },
          data: { resolved: true, resolvedAt: new Date() }
        });
      }

      // Notificar a los clientes conectados a través de WebSocket
      this.notifyStatusChange(updatedCamera);

      logger.info(`Heartbeat check for camera ${camera.name} (${camera.id}): ${isOnline ? 'ONLINE' : 'OFFLINE'}`);
      return isOnline;
    } catch (error) {
      logger.error(`Error checking status for camera ${cameraId}:`, error);
      
      // Registrar el error en la base de datos
      await this.prisma.failedHeartbeat.create({
        data: {
          cameraId,
          reason: 'Error during heartbeat check',
          details: error instanceof Error ? error.message : String(error)
        }
      });
      
      return false;
    }
  }

  /**
   * Notifica a los clientes conectados sobre un cambio de estado
   */
  private notifyStatusChange(camera: any): void {
    try {
      if (!io) {
        logger.warn('Socket.IO not initialized, cannot send status update');
        return;
      }

      io.to(`camera:${camera.id}`).emit('camera:status', {
        cameraId: camera.id,
        isOnline: camera.isOnline,
        status: camera.status,
        lastSeen: camera.lastSeen,
        uptime: camera.uptime
      });

      // Notificar también a la sala del usuario
      if (camera.userId) {
        io.to(`user:${camera.userId}`).emit('camera:status', {
          cameraId: camera.id,
          isOnline: camera.isOnline,
          status: camera.status,
          lastSeen: camera.lastSeen,
          uptime: camera.uptime
        });
      }
    } catch (error) {
      logger.error('Error notifying status change:', error);
    }
  }

  /**
   * Cierra el worker y libera recursos
   */
  public async close(): Promise<void> {
    if (this.intervalId) {
      clearInterval(this.intervalId);
    }
    
    if (this.worker) {
      await this.worker.close();
    }
    
    await this.prisma.$disconnect();
  }
}

// Exportar una instancia del worker
export const heartbeatWorker = new HeartbeatWorker();

export default heartbeatWorker;
