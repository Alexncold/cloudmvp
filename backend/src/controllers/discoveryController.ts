import { Request, Response, NextFunction } from 'express';
import { validationResult } from 'express-validator';
import { v4 as uuidv4 } from 'uuid';
import { Worker } from 'bullmq';
import { createClient, RedisClientType } from 'redis';
import { io } from '../config/socket';
import { DiscoveryJobData, DiscoveryJobResult, DiscoveryStatus, DiscoveryPhase, DiscoveryOptions, DiscoveryDevice } from '../../shared/types/discovery';
import { NetworkValidator } from '../services/networkValidator';
import { logger } from '../utils/logger';
import { ApiError } from '../utils/errors';

// Tipos personalizados
type DiscoverySession = {
  id: string;
  userId: string;
  status: DiscoveryStatus;
  phase: DiscoveryPhase;
  progress: number;
  startTime: Date;
  endTime?: Date;
  options: DiscoveryOptions;
  devices: DiscoveryDevice[];
  error?: string;
};

// Clase del controlador de descubrimiento
export class DiscoveryController {
  private static instance: DiscoveryController;
  private redisClient: RedisClientType;
  private networkValidator: NetworkValidator;
  private discoverySessions: Map<string, DiscoverySession> = new Map();
  private worker: Worker<DiscoveryJobData, DiscoveryJobResult, string>;
  private readonly SESSION_PREFIX = 'discovery:session:';
  private readonly SESSION_TTL = 24 * 60 * 60; // 24 horas en segundos
  
  private constructor() {
    // Inicializar el cliente de Redis
    this.redisClient = createClient({
      url: process.env.REDIS_URL || 'redis://localhost:6379',
      socket: {
        tls: process.env.NODE_ENV === 'production',
        rejectUnauthorized: false,
        reconnectStrategy: (retries) => {
          if (retries > 5) {
            logger.error('Demasiados intentos de reconexión a Redis');
            return new Error('Demasiados intentos de reconexión a Redis');
          }
          return Math.min(retries * 1000, 5000);
        },
      },
    });
    
    // Conectar a Redis
    this.redisClient.on('error', (err) => {
      logger.error('Error en el cliente Redis:', err);
    });
    
    // Inicializar el validador de red
    this.networkValidator = NetworkValidator.getInstance();
    
    // Inicializar el worker de descubrimiento
    this.worker = new Worker<DiscoveryJobData, DiscoveryJobResult, string>(
      'discovery-queue',
      `${__dirname}/../workers/discoveryWorker.js`,
      {
        connection: {
          host: process.env.REDIS_HOST || 'localhost',
          port: parseInt(process.env.REDIS_PORT || '6379', 10),
          password: process.env.REDIS_PASSWORD,
          tls: process.env.NODE_ENV === 'production' ? {} : undefined,
        },
        concurrency: parseInt(process.env.DISCOVERY_CONCURRENCY || '3', 10),
        removeOnComplete: { count: 100 },
        removeOnFail: { count: 1000 },
      }
    );
    
    // Configurar manejadores de eventos del worker
    this.setupWorkerHandlers();
    
    // Conectar a Redis al iniciar
    this.connectRedis();
  }
  
  // Obtener la instancia única del controlador (Singleton)
  public static getInstance(): DiscoveryController {
    if (!DiscoveryController.instance) {
      DiscoveryController.instance = new DiscoveryController();
    }
    return DiscoveryController.instance;
  }
  
  // Conectar a Redis
  private async connectRedis(): Promise<void> {
    try {
      await this.redisClient.connect();
      logger.info('Conectado a Redis exitosamente');
    } catch (error) {
      logger.error('Error al conectar a Redis:', error);
      throw new Error('No se pudo conectar a Redis');
    }
  }
  
  // Configurar manejadores de eventos del worker
  private setupWorkerHandlers(): void {
    // Progreso del trabajo
    this.worker.on('progress', async (job, progress) => {
      const sessionId = job.data.sessionId;
      const session = await this.getSession(sessionId);
      
      if (session) {
        session.progress = progress.progress;
        session.phase = progress.phase;
        session.status = progress.status;
        
        // Actualizar en memoria
        this.discoverySessions.set(sessionId, session);
        
        // Actualizar en Redis
        await this.saveSession(session);
        
        // Notificar a través de WebSocket
        io.to(`discovery:${sessionId}`).emit('discovery:progress', {
          sessionId,
          progress: session.progress,
          phase: session.phase,
          status: session.status,
          scanned: progress.scanned || 0,
          total: progress.total || 0,
        });
      }
    });
    
    // Dispositivo encontrado
    this.worker.on('deviceFound', async (job, device) => {
      const sessionId = job.data.sessionId;
      const session = await this.getSession(sessionId);
      
      if (session) {
        // Verificar si el dispositivo ya existe en la sesión
        const deviceIndex = session.devices.findIndex(d => d.id === device.id);
        
        if (deviceIndex === -1) {
          // Añadir nuevo dispositivo
          session.devices.push(device);
        } else {
          // Actualizar dispositivo existente
          session.devices[deviceIndex] = device;
        }
        
        // Actualizar en memoria
        this.discoverySessions.set(sessionId, session);
        
        // Actualizar en Redis (sincronización parcial para mejor rendimiento)
        await this.redisClient.hSet(
          `${this.SESSION_PREFIX}${sessionId}:devices`,
          device.id,
          JSON.stringify(device)
        );
        
        // Notificar a través de WebSocket
        io.to(`discovery:${sessionId}`).emit('discovery:device', device);
      }
    });
    
    // Error en el trabajo
    this.worker.on('error', (err) => {
      logger.error('Error en el worker de descubrimiento:', err);
    });
    
    // Trabajo completado
    this.worker.on('completed', async (job, result) => {
      const sessionId = job.data.sessionId;
      const session = await this.getSession(sessionId);
      
      if (session) {
        session.status = 'completed';
        session.progress = 100;
        session.endTime = new Date();
        
        // Actualizar en memoria
        this.discoverySessions.set(sessionId, session);
        
        // Actualizar en Redis
        await this.saveSession(session);
        
        // Notificar a través de WebSocket
        io.to(`discovery:${sessionId}`).emit('discovery:complete', {
          sessionId,
          totalDevices: session.devices.length,
          status: session.status,
          endTime: session.endTime,
        });
      }
    });
    
    // Trabajo fallido
    this.worker.on('failed', async (job, err) => {
      const sessionId = job?.data?.sessionId;
      
      if (sessionId) {
        const session = await this.getSession(sessionId);
        
        if (session) {
          session.status = 'failed';
          session.error = err.message;
          session.endTime = new Date();
          
          // Actualizar en memoria
          this.discoverySessions.set(sessionId, session);
          
          // Actualizar en Redis
          await this.saveSession(session);
          
          // Notificar a través de WebSocket
          io.to(`discovery:${sessionId}`).emit('discovery:error', {
            sessionId,
            error: err.message,
            status: session.status,
          });
        }
      }
      
      logger.error(`Error en el trabajo de descubrimiento ${job?.id}:`, err);
    });
  }
  
  // Obtener una sesión de descubrimiento
  private async getSession(sessionId: string): Promise<DiscoverySession | null> {
    // Primero verificar en memoria
    if (this.discoverySessions.has(sessionId)) {
      return this.discoverySessions.get(sessionId)!;
    }
    
    try {
      // Si no está en memoria, buscar en Redis
      const sessionData = await this.redisClient.get(`${this.SESSION_PREFIX}${sessionId}`);
      
      if (!sessionData) {
        return null;
      }
      
      const session = JSON.parse(sessionData);
      
      // Cargar dispositivos desde Redis
      const devices = await this.redisClient.hGetAll(`${this.SESSION_PREFIX}${sessionId}:devices`);
      session.devices = Object.values(devices).map(device => JSON.parse(device));
      
      // Almacenar en caché en memoria
      this.discoverySessions.set(sessionId, session);
      
      return session;
    } catch (error) {
      logger.error('Error al obtener la sesión de Redis:', error);
      return null;
    }
  }
  
  // Guardar una sesión de descubrimiento
  private async saveSession(session: DiscoverySession): Promise<void> {
    try {
      // Guardar en memoria
      this.discoverySessions.set(session.id, session);
      
      // Guardar en Redis
      const pipeline = this.redisClient.multi();
      
      // Guardar metadatos de la sesión
      const { devices, ...sessionData } = session;
      pipeline.setEx(
        `${this.SESSION_PREFIX}${session.id}`,
        this.SESSION_TTL,
        JSON.stringify(sessionData)
      );
      
      // Guardar dispositivos en un hash separado
      if (devices && devices.length > 0) {
        const deviceEntries = devices.flatMap(device => [
          device.id,
          JSON.stringify(device)
        ]);
        
        pipeline.hSet(`${this.SESSION_PREFIX}${session.id}:devices`, ...deviceEntries);
        
        // Establecer TTL para el hash de dispositivos
        pipeline.expire(
          `${this.SESSION_PREFIX}${session.id}:devices`,
          this.SESSION_TTL
        );
      }
      
      await pipeline.exec();
    } catch (error) {
      logger.error('Error al guardar la sesión en Redis:', error);
      throw new Error('Error al guardar la sesión de descubrimiento');
    }
  }
  
  // Validar opciones de descubrimiento
  private validateDiscoveryOptions(options: any): DiscoveryOptions {
    const defaultOptions: DiscoveryOptions = {
      networkRanges: ['192.168.1.0/24'],
      scanPorts: [80, 443, 554, 8000, 8080, 37777],
      protocols: ['onvif', 'rtsp', 'http'],
      timeout: 30000,
      maxConcurrentScans: 10,
      credentials: [
        { username: 'admin', password: 'admin' },
        { username: 'admin', password: '12345' },
        { username: 'admin', password: 'password' },
      ],
    };
    
    // Aplicar opciones proporcionadas
    const validatedOptions: DiscoveryOptions = {
      ...defaultOptions,
      ...options,
    };
    
    // Validar rangos de red
    if (validatedOptions.networkRanges && Array.isArray(validatedOptions.networkRanges)) {
      validatedOptions.networkRanges = validatedOptions.networkRanges.filter(range => 
        this.networkValidator.isValidCidr(range)
      );
      
      if (validatedOptions.networkRanges.length === 0) {
        throw new ApiError('No se proporcionaron rangos de red válidos', 400);
      }
      
      // Verificar que los rangos de red estén permitidos
      const allowedRanges = process.env.ALLOWED_NETWORK_RANGES?.split(',') || [];
      
      for (const range of validatedOptions.networkRanges) {
        if (!this.networkValidator.isNetworkAllowed(range, allowedRanges)) {
          throw new ApiError(`El rango de red ${range} no está permitido`, 403);
        }
      }
    }
    
    // Validar puertos
    if (validatedOptions.scanPorts && Array.isArray(validatedOptions.scanPorts)) {
      validatedOptions.scanPorts = validatedOptions.scanPorts
        .map(port => parseInt(port as any, 10))
        .filter(port => !isNaN(port) && port > 0 && port <= 65535);
    }
    
    // Validar protocolos
    if (validatedOptions.protocols && Array.isArray(validatedOptions.protocols)) {
      validatedOptions.protocols = validatedOptions.protocols.filter(protocol =>
        ['onvif', 'rtsp', 'http', 'https', 'rtmp'].includes(protocol)
      );
    }
    
    // Validar tiempo de espera
    const maxTimeout = parseInt(process.env.DISCOVERY_MAX_TIMEOUT || '300000', 10);
    if (validatedOptions.timeout > maxTimeout) {
      validatedOptions.timeout = maxTimeout;
    }
    
    // Validar escaneos concurrentes
    const maxConcurrent = parseInt(process.env.MAX_CONCURRENT_SCANS || '20', 10);
    if (validatedOptions.maxConcurrentScans > maxConcurrent) {
      validatedOptions.maxConcurrentScans = maxConcurrent;
    }
    
    return validatedOptions;
  }
  
  // ==================== MÉTODOS DEL CONTROLADOR ====================
  
  /**
   * Iniciar un nuevo descubrimiento de cámaras
   */
  public startDiscovery = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      // Validar la solicitud
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        throw new ApiError('Parámetros inválidos', 400, { errors: errors.array() });
      }
      
      // Obtener ID de usuario autenticado
      const userId = req.user?.id || 'system';
      
      // Validar y normalizar opciones de descubrimiento
      const discoveryOptions = this.validateDiscoveryOptions(req.body);
      
      // Crear una nueva sesión de descubrimiento
      const sessionId = uuidv4();
      const session: DiscoverySession = {
        id: sessionId,
        userId,
        status: 'pending',
        phase: 'initializing',
        progress: 0,
        startTime: new Date(),
        options: discoveryOptions,
        devices: [],
      };
      
      // Guardar la sesión en Redis
      await this.saveSession(session);
      
      // Iniciar el trabajo de descubrimiento en segundo plano
      await this.worker.add(
        'discovery-job',
        {
          sessionId,
          options: discoveryOptions,
          userId,
        },
        {
          jobId: sessionId,
          removeOnComplete: true,
          removeOnFail: true,
          attempts: 3,
          backoff: {
            type: 'exponential',
            delay: 5000,
          },
        }
      );
      
      // Actualizar el estado de la sesión
      session.status = 'running';
      session.phase = 'scanning';
      await this.saveSession(session);
      
      // Responder con los detalles de la sesión
      res.status(202).json({
        success: true,
        message: 'Descubrimiento de cámaras iniciado',
        sessionId,
        status: session.status,
        progress: session.progress,
        startTime: session.startTime,
      });
      
      logger.info(`Sesión de descubrimiento iniciada: ${sessionId} por el usuario ${userId}`);
    } catch (error) {
      next(error);
    }
  };
  
  /**
   * Obtener el estado actual de una sesión de descubrimiento
   */
  public getDiscoveryStatus = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const { sessionId } = req.params;
      const userId = req.user?.id;
      
      // Obtener la sesión
      const session = await this.getSession(sessionId);
      
      if (!session) {
        throw new ApiError('Sesión de descubrimiento no encontrada', 404);
      }
      
      // Verificar permisos (solo el propietario o un administrador puede ver la sesión)
      if (session.userId !== userId && !req.user?.isAdmin) {
        throw new ApiError('No autorizado para ver esta sesión', 403);
      }
      
      // Devolver el estado de la sesión
      res.json({
        success: true,
        sessionId: session.id,
        status: session.status,
        phase: session.phase,
        progress: session.progress,
        startTime: session.startTime,
        endTime: session.endTime,
        devicesCount: session.devices?.length || 0,
        error: session.error,
      });
    } catch (error) {
      next(error);
    }
  };
  
  /**
   * Obtener los dispositivos descubiertos en una sesión
   */
  public getDiscoveredDevices = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const { sessionId } = req.params;
      const { page = 1, limit = 50 } = req.query;
      const userId = req.user?.id;
      
      // Validar parámetros de paginación
      const pageNum = parseInt(page as string, 10) || 1;
      const limitNum = Math.min(parseInt(limit as string, 10) || 50, 100);
      const offset = (pageNum - 1) * limitNum;
      
      // Obtener la sesión
      const session = await this.getSession(sessionId);
      
      if (!session) {
        throw new ApiError('Sesión de descubrimiento no encontrada', 404);
      }
      
      // Verificar permisos
      if (session.userId !== userId && !req.user?.isAdmin) {
        throw new ApiError('No autorizado para ver los dispositivos de esta sesión', 403);
      }
      
      // Obtener dispositivos paginados
      const devices = session.devices || [];
      const paginatedDevices = devices.slice(offset, offset + limitNum);
      
      // Devolver los dispositivos con metadatos de paginación
      res.json({
        success: true,
        sessionId: session.id,
        status: session.status,
        total: devices.length,
        page: pageNum,
        limit: limitNum,
        totalPages: Math.ceil(devices.length / limitNum),
        devices: paginatedDevices,
      });
    } catch (error) {
      next(error);
    }
  };
  
  /**
   * Cancelar un descubrimiento en curso
   */
  public cancelDiscovery = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const { sessionId } = req.params;
      const userId = req.user?.id;
      
      // Obtener la sesión
      const session = await this.getSession(sessionId);
      
      if (!session) {
        throw new ApiError('Sesión de descubrimiento no encontrada', 404);
      }
      
      // Verificar permisos
      if (session.userId !== userId && !req.user?.isAdmin) {
        throw new ApiError('No autorizado para cancelar esta sesión', 403);
      }
      
      // Verificar si el descubrimiento está en curso
      if (session.status !== 'running') {
        throw new ApiError('El descubrimiento no está en curso', 400);
      }
      
      // Actualizar el estado de la sesión
      session.status = 'cancelled';
      session.endTime = new Date();
      session.error = 'Cancelado por el usuario';
      
      // Guardar los cambios
      await this.saveSession(session);
      
      // Notificar a través de WebSocket
      io.to(`discovery:${sessionId}`).emit('discovery:cancelled', {
        sessionId,
        status: session.status,
        endTime: session.endTime,
      });
      
      // Intentar cancelar el trabajo en el worker
      try {
        const job = await this.worker.getJob(sessionId);
        if (job) {
          await job.moveToFailed(new Error('Cancelado por el usuario'), '');
        }
      } catch (error) {
        logger.error('Error al cancelar el trabajo del worker:', error);
      }
      
      // Responder al cliente
      res.json({
        success: true,
        message: 'Descubrimiento cancelado correctamente',
        sessionId: session.id,
        status: session.status,
        endTime: session.endTime,
      });
      
      logger.info(`Sesión de descubrimiento cancelada: ${sessionId} por el usuario ${userId}`);
    } catch (error) {
      next(error);
    }
  };
  
  /**
   * Obtener el historial de descubrimientos del usuario
   */
  public getDiscoveryHistory = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const userId = req.user?.id;
      const { page = 1, limit = 20 } = req.query;
      
      // Validar parámetros de paginación
      const pageNum = parseInt(page as string, 10) || 1;
      const limitNum = Math.min(parseInt(limit as string, 10) || 20, 50);
      const offset = (pageNum - 1) * limitNum;
      
      // En un entorno de producción real, esto consultaría la base de datos
      // Para este ejemplo, simulamos la paginación con las sesiones en memoria
      const userSessions = Array.from(this.discoverySessions.values())
        .filter(session => session.userId === userId || req.user?.isAdmin)
        .sort((a, b) => b.startTime.getTime() - a.startTime.getTime());
      
      const paginatedSessions = userSessions.slice(offset, offset + limitNum);
      
      // Formatear la respuesta
      const sessions = paginatedSessions.map(session => ({
        id: session.id,
        status: session.status,
        phase: session.phase,
        progress: session.progress,
        startTime: session.startTime,
        endTime: session.endTime,
        devicesCount: session.devices?.length || 0,
        error: session.error,
      }));
      
      res.json({
        success: true,
        total: userSessions.length,
        page: pageNum,
        limit: limitNum,
        totalPages: Math.ceil(userSessions.length / limitNum),
        sessions,
      });
    } catch (error) {
      next(error);
    }
  };
  
  /**
   * Exportar dispositivos descubiertos en formato CSV o JSON
   */
  public exportDevices = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const { sessionId } = req.params;
      const { format = 'json' } = req.query;
      const userId = req.user?.id;
      
      // Obtener la sesión
      const session = await this.getSession(sessionId);
      
      if (!session) {
        throw new ApiError('Sesión de descubrimiento no encontrada', 404);
      }
      
      // Verificar permisos
      if (session.userId !== userId && !req.user?.isAdmin) {
        throw new ApiError('No autorizado para exportar los dispositivos de esta sesión', 403);
      }
      
      // Verificar si hay dispositivos para exportar
      if (!session.devices || session.devices.length === 0) {
        throw new ApiError('No hay dispositivos para exportar', 400);
      }
      
      // Exportar en el formato solicitado
      if (format === 'csv') {
        // Convertir a CSV
        const header = Object.keys(session.devices[0]).join(',');
        const rows = session.devices.map(device => 
          Object.values(device).map(field => 
            typeof field === 'string' ? `"${field.replace(/"/g, '""')}"` : field
          ).join(',')
        );
        
        const csvContent = [header, ...rows].join('\n');
        
        // Enviar el archivo CSV
        res.setHeader('Content-Type', 'text/csv');
        res.setHeader('Content-Disposition', `attachment; filename=devices_${sessionId}.csv`);
        res.send(csvContent);
      } else {
        // Exportar como JSON por defecto
        res.setHeader('Content-Type', 'application/json');
        res.setHeader('Content-Disposition', `attachment; filename=devices_${sessionId}.json`);
        res.send(JSON.stringify(session.devices, null, 2));
      }
    } catch (error) {
      next(error);
    }
  };
  
  /**
   * Middleware para manejar la conexión de WebSocket para una sesión de descubrimiento
   */
  public handleWebSocketConnection = (socket: any): void => {
    const sessionId = socket.handshake.query.sessionId;
    const userId = socket.request.user?.id;
    
    if (!sessionId) {
      socket.disconnect(true);
      return;
    }
    
    // Unirse a la sala de la sesión
    socket.join(`discovery:${sessionId}`);
    
    // Obtener el estado actual de la sesión y enviarlo al cliente
    this.getSession(sessionId)
      .then(session => {
        if (!session) {
          socket.emit('discovery:error', { error: 'Sesión no encontrada' });
          socket.disconnect(true);
          return;
        }
        
        // Verificar permisos
        if (session.userId !== userId && !socket.request.user?.isAdmin) {
          socket.emit('discovery:error', { error: 'No autorizado' });
          socket.disconnect(true);
          return;
        }
        
        // Enviar el estado actual de la sesión
        socket.emit('discovery:status', {
          sessionId: session.id,
          status: session.status,
          phase: session.phase,
          progress: session.progress,
          startTime: session.startTime,
          endTime: session.endTime,
          devicesCount: session.devices?.length || 0,
          error: session.error,
        });
        
        // Si hay dispositivos, enviar la lista completa
        if (session.devices && session.devices.length > 0) {
          // Enviar los últimos 50 dispositivos para evitar sobrecargar el cliente
          const recentDevices = session.devices.slice(-50);
          socket.emit('discovery:devices', recentDevices);
        }
      })
      .catch(error => {
        logger.error('Error en la conexión WebSocket:', error);
        socket.emit('discovery:error', { error: 'Error al cargar la sesión' });
        socket.disconnect(true);
      });
    
    // Manejar mensajes del cliente
    socket.on('discovery:status', () => {
      // El cliente solicita el estado actual
      this.getSession(sessionId)
        .then(session => {
          if (session) {
            socket.emit('discovery:status', {
              sessionId: session.id,
              status: session.status,
              phase: session.phase,
              progress: session.progress,
              startTime: session.startTime,
              endTime: session.endTime,
              devicesCount: session.devices?.length || 0,
              error: session.error,
            });
          }
        })
        .catch(error => {
          logger.error('Error al obtener el estado de la sesión:', error);
        });
    });
    
    // Manejar desconexión
    socket.on('disconnect', () => {
      logger.debug(`Cliente desconectado de la sesión ${sessionId}`);
    });
  };
}

// Exportar una instancia del controlador
export const discoveryController = DiscoveryController.getInstance();
