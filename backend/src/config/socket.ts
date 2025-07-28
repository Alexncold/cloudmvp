import { Server as HttpServer } from 'http';
import { Server as SocketIOServer, Socket } from 'socket.io';
import { socketAuth, socketLogger, socketRoleAuth } from '../middleware/socketAuth';
import { logger } from '../utils/logger';
import { discoveryWorker } from '../workers/discoveryWorker';
import { DiscoveryOptions } from '../../../shared/types/discovery';

// Configuración de CORS para Socket.IO
const corsOptions = {
  origin: process.env.NODE_ENV === 'production'
    ? process.env.ALLOWED_ORIGINS?.split(',').map(origin => origin.trim())
    : '*',
  methods: ['GET', 'POST'],
  credentials: true,
  allowedHeaders: ['Authorization'],
  transports: ['websocket', 'polling']
};

// Configuración de seguridad para Socket.IO
const socketOptions = {
  cors: corsOptions,
  serveClient: false, // No servir el cliente de Socket.IO
  path: '/socket.io', // Ruta base para las conexiones Socket.IO
  connectTimeout: 45000, // 45 segundos de timeout para la conexión
  pingTimeout: 25000,   // 25 segundos para marcar la conexión como inactiva
  pingInterval: 10000,  // Enviar ping cada 10 segundos
  maxHttpBufferSize: 1e6, // 1MB máximo por mensaje
  allowRequest: (req: any, callback: (err: string | null, success: boolean) => void) => {
    // Validación adicional de origen si es necesario
    const origin = req.headers.origin || req.headers.referer;
    if (process.env.NODE_ENV === 'production' && origin) {
      const allowedOrigins = process.env.ALLOWED_ORIGINS?.split(',').map(o => o.trim());
      if (allowedOrigins && !allowedOrigins.some(o => origin.startsWith(o))) {
        logger.warn(`Intento de conexión desde origen no permitido: ${origin}`);
        return callback('Origen no permitido', false);
      }
    }
    callback(null, true);
  }
};

/**
 * Inicializa y configura el servidor Socket.IO
 */
const initializeSocket = (httpServer: HttpServer): SocketIOServer => {
  // Crear instancia de Socket.IO
  const io = new SocketIOServer(httpServer, socketOptions);
  
  // Middleware de autenticación global
  io.use(socketAuth);
  io.use(socketLogger);
  
  // Espacio de nombres para el descubrimiento de cámaras
  const discoveryNamespace = io.of('/discovery');
  
  // Aplicar autenticación al espacio de nombres de descubrimiento
  discoveryNamespace.use(socketAuth);
  discoveryNamespace.use(socketRoleAuth(['admin', 'operator']));
  
  // Configurar manejadores de eventos para el espacio de nombres de descubrimiento
  discoveryNamespace.on('connection', (socket: Socket) => {
    logger.info(`Nueva conexión de descubrimiento: ${socket.id}`);
    
    // Manejar inicio de descubrimiento
    socket.on('discovery:start', async (options: DiscoveryOptions, callback) => {
      try {
        logger.info(`Iniciando descubrimiento para la sesión: ${options.sessionId}`);
        
        // Validar opciones
        if (!options.networkRanges || options.networkRanges.length === 0) {
          throw new Error('Se requiere al menos un rango de red');
        }
        
        // Iniciar el trabajo de descubrimiento
        await discoveryWorker.startDiscovery({
          ...options,
          userId: socket.user?.id || 'system',
          sessionId: options.sessionId || `sess_${Date.now()}`,
          socketId: socket.id
        });
        
        // Confirmar que el descubrimiento ha comenzado
        callback({
          success: true,
          message: 'Descubrimiento iniciado',
          sessionId: options.sessionId
        });
        
      } catch (error) {
        logger.error('Error al iniciar el descubrimiento:', error);
        callback({
          success: false,
          error: error instanceof Error ? error.message : 'Error desconocido'
        });
      }
    });
    
    // Manejar cancelación de descubrimiento
    socket.on('discovery:cancel', async (sessionId: string, callback) => {
      try {
        logger.info(`Cancelando descubrimiento para la sesión: ${sessionId}`);
        await discoveryWorker.cancelDiscovery(sessionId);
        callback({ success: true, message: 'Descubrimiento cancelado' });
      } catch (error) {
        logger.error('Error al cancelar el descubrimiento:', error);
        callback({
          success: false,
          error: error instanceof Error ? error.message : 'Error desconocido'
        });
      }
    });
    
    // Manejar solicitud de estado de descubrimiento
    socket.on('discovery:status', async (sessionId: string, callback) => {
      try {
        const status = await discoveryWorker.getDiscoveryStatus(sessionId);
        callback({ success: true, status });
      } catch (error) {
        logger.error('Error al obtener el estado del descubrimiento:', error);
        callback({
          success: false,
          error: error instanceof Error ? error.message : 'Error desconocido'
        });
      }
    });
    
    // Manejar desconexión
    socket.on('disconnect', (reason) => {
      logger.info(`Conexión de descubrimiento cerrada: ${socket.id} - ${reason}`);
      // Opcional: Cancelar descubrimientos activos de este socket
    });
  });
  
  // Espacio de nombres para notificaciones en tiempo real
  const notificationsNamespace = io.of('/notifications');
  notificationsNamespace.use(socketAuth);
  
  notificationsNamespace.on('connection', (socket: Socket) => {
    logger.info(`Nueva conexión de notificaciones: ${socket.id}`);
    
    // Unir al usuario a su sala personal para notificaciones
    if (socket.user) {
      socket.join(`user:${socket.user.id}`);
      
      // Unir a canales adicionales según el rol
      if (socket.user.role === 'admin') {
        socket.join('admin:notifications');
      }
    }
    
    // Manejar suscripción a canales específicos
    socket.on('subscribe', (channel: string) => {
      if (typeof channel === 'string') {
        socket.join(channel);
        logger.debug(`Socket ${socket.id} suscrito a ${channel}`);
      }
    });
    
    // Manejar desuscripción de canales
    socket.on('unsubscribe', (channel: string) => {
      if (typeof channel === 'string') {
        socket.leave(channel);
        logger.debug(`Socket ${socket.id} desuscrito de ${channel}`);
      }
    });
  });
  
  // Manejar errores globales de Socket.IO
  io.engine.on('connection_error', (err) => {
    logger.error('Error de conexión de Socket.IO:', {
      message: err.message,
      code: err.code,
      context: err.context,
      stack: err.stack
    });
  });
  
  logger.info('Socket.IO configurado correctamente');
  return io;
};

// Tipos para TypeScript
declare module 'http' {
  interface Server {
    io?: SocketIOServer;
  }
}

export { initializeSocket };
