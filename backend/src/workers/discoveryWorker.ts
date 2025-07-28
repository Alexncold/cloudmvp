import { Worker, Job } from 'bullmq';
import { Redis } from 'ioredis';
import { logger } from '../utils/logger';
import { NetworkValidator } from '../services/networkValidator';
import { 
  DiscoveryOptions, 
  DiscoveryProgress, 
  DiscoveryResult, 
  DiscoveryStatus,
  SecurityLevel,
  CameraDevice,
  CameraProtocol
} from '../../../shared/types/discovery';
import { io } from '../app';
import * as net from 'net';
import * as dns from 'dns';
import * as ping from 'ping';
import { URL } from 'url';
import { createHash } from 'crypto';

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
const WORKER_CONCURRENCY = parseInt(process.env.MAX_CONCURRENT_SCANS || '3');
const DISCOVERY_TIMEOUT = parseInt(process.env.DISCOVERY_TIMEOUT || '60000');
const MAX_SCAN_THREADS = parseInt(process.env.MAX_SCAN_THREADS || '20');

// Puertos comunes para cámaras IP
const COMMON_CAMERA_PORTS = [
  80, 81, 82, 83, 84, 85, 86, 87, 88, 89, // HTTP
  443, 444, 445, 446, 447, 448, 449, // HTTPS
  554, 555, 556, 557, 558, 559, // RTSP
  1935, 1936, // RTMP
  8000, 8001, 8002, 8003, 8004, 8005, 8006, 8007, 8008, 8009, // HTTP alternativos
  8080, 8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089, // HTTP alternativos
  8899, 9000, 9001, 9002, 9003, 9004, 9005, 9006, 9007, 9008, 9009, // Varios
  10080, 10081, 10082, 10083, 10084, 10085, 10086, 10087, 10088, 10089,
  20000, 20001, 20002, 20003, 20004, 20005, 20006, 20007, 20008, 20009,
  37777, 37778, 37779, // Dahua
  80, 443, 8000, 8080, 8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089, // HTTP/HTTPS
  554, 555, 8554, // RTSP
  1935, 1936, // RTMP
  37777, 37778, 37779, // Dahua
  80, 81, 82, 83, 84, 85, 86, 87, 88, 89, // HTTP alternativos
  8080, 8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089, // HTTP alternativos
  8899, 9000, 9001, 9002, 9003, 9004, 9005, 9006, 9007, 9008, 9009, // Varios
];

// Credenciales por defecto para probar en cámaras
const DEFAULT_CREDENTIALS = [
  { username: 'admin', password: 'admin' },
  { username: 'admin', password: 'password' },
  { username: 'admin', password: '12345' },
  { username: 'admin', password: '1234' },
  { username: 'admin', password: '123456' },
  { username: 'admin', password: '12345678' },
  { username: 'admin', password: '123456789' },
  { username: 'admin', password: 'admin123' },
  { username: 'admin', password: 'admin1234' },
  { username: 'admin', password: 'admin12345' },
  { username: 'admin', password: 'admin123456' },
  { username: 'admin', password: 'admin12345678' },
  { username: 'admin', password: 'adminadmin' },
  { username: 'admin', password: 'admin@123' },
  { username: 'admin', password: 'admin@1234' },
  { username: 'admin', password: 'admin@12345' },
  { username: 'admin', password: 'admin@123456' },
  { username: 'admin', password: 'admin@12345678' },
  { username: 'admin', password: 'admin@admin' },
  { username: 'admin', password: 'admin@password' },
  { username: 'admin', password: 'admin@123456789' },
  { username: 'admin', password: 'admin@1234567890' },
];

/**
 * Clase principal del worker de descubrimiento
 */
class DiscoveryWorker {
  private worker: Worker;
  private networkValidator: NetworkValidator;
  private activeScans: Map<string, boolean> = new Map();
  private scanTimeouts: Map<string, NodeJS.Timeout> = new Map();

  constructor() {
    this.networkValidator = new NetworkValidator();
    this.initializeWorker();
  }

  /**
   * Inicializa el worker de BullMQ
   */
  private initializeWorker() {
    this.worker = new Worker<DiscoveryOptions>(
      'discovery-queue',
      async (job) => {
        try {
          await this.processDiscoveryJob(job);
        } catch (error) {
          logger.error(`Error en el trabajo de descubrimiento ${job.id}:`, error);
          throw error;
        }
      },
      {
        connection: redis,
        concurrency: WORKER_CONCURRENCY,
        removeOnComplete: { count: 100 },
        removeOnFail: { count: 1000 },
        lockDuration: 600000, // 10 minutos
        lockRenewTime: 30000, // 30 segundos
      }
    );

    // Manejar eventos del worker
    this.setupWorkerEvents();
  }

  /**
   * Configura los manejadores de eventos del worker
   */
  private setupWorkerEvents() {
    this.worker.on('completed', (job: Job) => {
      const { userId, sessionId } = job.data;
      logger.info(`Trabajo de descubrimiento completado: ${job.id} para el usuario ${userId}`);
      
      // Limpiar timeout si existe
      this.clearScanTimeout(sessionId);
      
      // Emitir evento de finalización
      io.to(`user:${userId}`).emit('discovery:complete', {
        taskId: job.id,
        sessionId,
        status: 'completed',
        completedOn: new Date()
      });
    });

    this.worker.on('failed', (job: Job | undefined, error: Error) => {
      const userId = job?.data?.userId;
      const sessionId = job?.data?.sessionId;
      
      logger.error(`Trabajo de descubrimiento fallido: ${job?.id}`, error);
      
      // Limpiar timeout si existe
      if (sessionId) {
        this.clearScanTimeout(sessionId);
      }
      
      // Emitir evento de error si hay un job
      if (job && userId && sessionId) {
        io.to(`user:${userId}`).emit('discovery:error', {
          taskId: job.id,
          sessionId,
          status: 'failed',
          error: error.message,
          failedReason: error.stack
        });
      }
    });

    this.worker.on('progress', (job: Job, progress: number) => {
      const { userId, sessionId } = job.data;
      
      // Emitir evento de progreso
      io.to(`user:${userId}`).emit('discovery:progress', {
        taskId: job.id,
        sessionId,
        progress,
        updatedAt: new Date()
      });
    });
  }

  /**
   * Procesa un trabajo de descubrimiento
   */
  private async processDiscoveryJob(job: Job<DiscoveryOptions>): Promise<DiscoveryResult> {
    const { userId, sessionId, networkRanges, securityLevel = 'standard' } = job.data;
    const startTime = new Date();
    
    try {
      // Validar rangos de red
      const validation = await this.networkValidator.validateRanges(networkRanges);
      if (!validation.isValidRange) {
        throw new Error(`Rangos de red no válidos: ${validation.securityRisks.join(', ')}`);
      }
      
      // Configurar timeout para el escaneo
      this.setupScanTimeout(sessionId, job);
      
      // Iniciar el proceso de descubrimiento
      await this.updateProgress(job, 0, 'Iniciando escaneo de red...', 'initializing');
      
      // Aquí iría la lógica de descubrimiento real
      // Por ahora, simulamos un descubrimiento
      const devices: CameraDevice[] = [];
      
      // Simular progreso
      for (let i = 0; i < 10; i++) {
        await new Promise(resolve => setTimeout(resolve, 500));
        await this.updateProgress(job, i * 10, `Escaneando red (${i + 1}/10)...`, 'network_scan');
        
        // Simular dispositivo encontrado
        if (i % 2 === 0) {
          const device: CameraDevice = this.generateMockDevice(`192.168.1.${i + 1}`);
          devices.push(device);
          
          // Emitir evento de dispositivo encontrado
          io.to(`user:${userId}`).emit('discovery:device', {
            taskId: job.id,
            sessionId,
            device
          });
        }
      }
      
      // Procesamiento final
      await this.updateProgress(job, 90, 'Finalizando escaneo...', 'finalizing');
      
      // Simular procesamiento final
      await new Promise(resolve => setTimeout(resolve, 1000));
      
      // Resultado final
      const endTime = new Date();
      const result: DiscoveryResult = {
        taskId: job.id,
        sessionId,
        status: 'completed',
        startTime,
        endTime,
        duration: endTime.getTime() - startTime.getTime(),
        devices,
        stats: {
          totalDevices: devices.length,
          devicesWithDefaultCredentials: devices.filter(d => d.security?.hasDefaultCredentials).length,
          devicesWithVulnerabilities: devices.filter(d => d.security?.vulnerabilities?.length > 0).length,
          totalVulnerabilities: devices.reduce((sum, d) => sum + (d.security?.vulnerabilities?.length || 0), 0),
          vulnerabilitiesBySeverity: {
            low: 0,
            medium: 0,
            high: 0,
            critical: 0
          }
        }
      };
      
      // Actualizar estadísticas de vulnerabilidades
      devices.forEach(device => {
        device.security?.vulnerabilities?.forEach(vuln => {
          result.stats.vulnerabilitiesBySeverity[vuln.severity]++;
        });
      });
      
      // Guardar resultados en caché
      await this.cacheDiscoveryResults(userId, sessionId, result);
      
      return result;
      
    } catch (error) {
      logger.error(`Error en el trabajo de descubrimiento ${job.id}:`, error);
      throw error;
    } finally {
      // Limpiar recursos
      this.cleanupScan(sessionId);
    }
  }
  
  /**
   * Actualiza el progreso del trabajo
   */
  private async updateProgress(
    job: Job<DiscoveryOptions>,
    progress: number,
    message: string,
    phase: string
  ): Promise<void> {
    const { userId, sessionId } = job.data;
    
    // Actualizar progreso en el trabajo
    await job.updateProgress(progress);
    
    // Emitir evento de progreso detallado
    const progressData: DiscoveryProgress = {
      taskId: job.id,
      sessionId,
      status: 'scanning' as DiscoveryStatus,
      phase: phase as any, // Convertir a tipo DiscoveryPhase
      progress,
      message,
      devicesFound: 0, // Se actualizará en el manejador de eventos
      updatedAt: new Date()
    };
    
    io.to(`user:${userId}`).emit('discovery:progress', progressData);
  }
  
  /**
   * Configura un timeout para el escaneo
   */
  private setupScanTimeout(sessionId: string, job: Job<DiscoveryOptions>): void {
    // Limpiar timeout existente si lo hay
    this.clearScanTimeout(sessionId);
    
    // Configurar nuevo timeout
    const timeout = setTimeout(async () => {
      try {
        logger.warn(`Timeout alcanzado para el escaneo ${sessionId}`);
        
        // Intentar cancelar el trabajo
        await job.discard();
        
        // Notificar al usuario
        io.to(`user:${job.data.userId}`).emit('discovery:timeout', {
          taskId: job.id,
          sessionId,
          message: 'El tiempo de escaneo ha excedido el límite permitido'
        });
        
      } catch (error) {
        logger.error('Error al manejar el timeout del escaneo:', error);
      } finally {
        this.cleanupScan(sessionId);
      }
    }, DISCOVERY_TIMEOUT);
    
    // Guardar referencia al timeout
    this.scanTimeouts.set(sessionId, timeout);
  }
  
  /**
   * Limpia el timeout de un escaneo
   */
  private clearScanTimeout(sessionId: string): void {
    const timeout = this.scanTimeouts.get(sessionId);
    if (timeout) {
      clearTimeout(timeout);
      this.scanTimeouts.delete(sessionId);
    }
  }
  
  /**
   * Limpia los recursos de un escaneo
   */
  private cleanupScan(sessionId: string): void {
    this.clearScanTimeout(sessionId);
    this.activeScans.delete(sessionId);
  }
  
  /**
   * Almacena en caché los resultados del descubrimiento
   */
  private async cacheDiscoveryResults(
    userId: string,
    sessionId: string,
    result: DiscoveryResult
  ): Promise<void> {
    const cacheKey = `discovery:results:${userId}:${sessionId}`;
    const cacheTtl = 24 * 60 * 60; // 24 horas
    
    try {
      await redis.setex(
        cacheKey,
        cacheTtl,
        JSON.stringify(result)
      );
    } catch (error) {
      logger.error('Error al guardar en caché los resultados del descubrimiento:', error);
    }
  }
  
  /**
   * Genera un dispositivo de cámara simulado para pruebas
   */
  private generateMockDevice(ip: string): CameraDevice {
    const manufacturers = ['Hikvision', 'Dahua', 'Axis', 'Bosch', 'Samsung', 'Sony', 'Panasonic', 'Honeywell'];
    const models = ['IPC-123', 'DHI-456', 'M1234', 'SND-1234', 'SNC-1234', 'WV-1234', 'VB-1234'];
    const protocols: CameraProtocol[] = ['onvif', 'rtsp', 'http'];
    
    const manufacturer = manufacturers[Math.floor(Math.random() * manufacturers.length)];
    const model = models[Math.floor(Math.random() * models.length)];
    const protocol = protocols[Math.floor(Math.random() * protocols.length)];
    const port = COMMON_CAMERA_PORTS[Math.floor(Math.random() * COMMON_CAMERA_PORTS.length)];
    
    const device: CameraDevice = {
      id: createHash('md5').update(`${ip}:${port}`).digest('hex'),
      ip,
      port,
      protocol,
      manufacturer,
      model,
      firmwareVersion: '1.0.0',
      name: `${manufacturer} ${model}`,
      location: 'Desconocido',
      requiresAuth: Math.random() > 0.3, // 70% de probabilidad de requerir autenticación
      webInterfaceUrl: `http://${ip}:${port}`,
      streamUrl: `rtsp://${ip}:${port}/stream1`,
      openPorts: [port, 80, 443, 554].filter((_, i) => Math.random() > 0.5),
      services: [
        { name: 'http', port: 80, protocol: 'tcp', secure: false },
        { name: 'https', port: 443, protocol: 'tcp', secure: true },
        { name: 'rtsp', port: 554, protocol: 'tcp', secure: false },
      ],
      security: {
        hasDefaultCredentials: Math.random() > 0.7, // 30% de probabilidad de credenciales por defecto
        isEncrypted: Math.random() > 0.5, // 50% de probabilidad de usar cifrado
        vulnerabilities: []
      },
      confidence: 0.9,
      lastSeen: new Date(),
      metadata: {
        discoveredAt: new Date().toISOString(),
        scanId: `scan-${Date.now()}`
      }
    };
    
    // Agregar algunas vulnerabilidades aleatorias
    if (Math.random() > 0.7) { // 30% de probabilidad de tener vulnerabilidades
      const vulns = [
        { id: 'CVE-2021-36260', name: 'Hikvision Command Injection', severity: 'critical' as const },
        { id: 'CVE-2021-33044', name: 'Dahua Authentication Bypass', severity: 'high' as const },
        { id: 'CVE-2020-25078', name: 'Samsung Wisenet XRN-410S XSS', severity: 'medium' as const },
        { id: 'CVE-2019-10999', name: 'Hikvision Backdoor', severity: 'critical' as const },
        { id: 'CVE-2018-9995', name: 'Dahua Authentication Bypass', severity: 'high' as const },
      ];
      
      const numVulns = Math.floor(Math.random() * 3) + 1; // 1-3 vulnerabilidades
      for (let i = 0; i < numVulns && i < vulns.length; i++) {
        const vuln = vulns[Math.floor(Math.random() * vulns.length)];
        if (!device.security) device.security = { hasDefaultCredentials: false, isEncrypted: false };
        if (!device.security.vulnerabilities) device.security.vulnerabilities = [];
        
        if (!device.security.vulnerabilities.some(v => v.id === vuln.id)) {
          device.security.vulnerabilities.push({
            ...vuln,
            description: `Vulnerabilidad de seguridad crítica en ${manufacturer} ${model}`,
            remediation: 'Actualizar el firmware a la última versión disponible.'
          });
        }
      }
    }
    
    return device;
  }
}

// Exportar una instancia del worker
export const discoveryWorker = new DiscoveryWorker();

export default discoveryWorker;
