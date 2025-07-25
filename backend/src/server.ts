// Configuración de paths de módulos (debe ser lo primero)
import 'tsconfig-paths/register';
import 'dotenv/config';

import { createServer, Server as HttpServer } from 'http';
import { Server as SocketIOServer, Socket } from 'socket.io';
import { logger } from './utils/logger';
import createApp from './app';

// Obtener el puerto del entorno o usar 3001 por defecto
const PORT = parseInt(process.env.PORT || '3001', 10);

// Variables para el servidor HTTP y Socket.IO
let httpServer: HttpServer;
let io: SocketIOServer;

/**
 * Inicializa la aplicación Express, el servidor HTTP y la configuración de Socket.IO
 */
async function initializeApp() {
  try {
    // Crear la aplicación Express
    const app = await createApp();
    
    // Crear servidor HTTP
    httpServer = createServer(app);
    
    // Configurar Socket.IO
    io = new SocketIOServer(httpServer, {
      cors: {
        origin: process.env.FRONTEND_URL || 'http://localhost:5173',
        methods: ['GET', 'POST'],
        credentials: true,
      },
      maxHttpBufferSize: 1e8, // 100MB
      pingTimeout: 60000, // 60 segundos
      pingInterval: 25000, // 25 segundos
    });
    
    // Configurar eventos de Socket.IO
    setupSocketIO();
    
    return { httpServer, io };
  } catch (error) {
    logger.error('Error al inicializar la aplicación:', error);
    throw error;
  }
}

/**
 * Configura los manejadores de eventos de Socket.IO
 */
function setupSocketIO() {
  if (!io) {
    throw new Error('Socket.IO no está inicializado');
  }
  
  io.on('connection', (socket: Socket) => {
    logger.info(`Nuevo cliente conectado: ${socket.id}`);
    
    // Manejar desconexión
    socket.on('disconnect', () => {
      logger.info(`Cliente desconectado: ${socket.id}`);
    });
    
    // Manejar errores
    socket.on('error', (error: Error) => {
      logger.error('Error en el socket:', { 
        socketId: socket.id,
        error: error.message, 
        stack: error.stack 
      });
    });
  });
}

/**
 * Inicia el servidor HTTP
 */
async function startServer(): Promise<HttpServer> {
  try {
    await initializeApp();
    
    return new Promise((resolve, reject) => {
      if (!httpServer) {
        return reject(new Error('El servidor HTTP no está inicializado'));
      }
      
      const server = httpServer.listen(PORT, '0.0.0.0', () => {
        logger.info(`Servidor escuchando en el puerto ${PORT}`);
        logger.info(`Entorno: ${process.env.NODE_ENV || 'development'}`);
        logger.info(`Documentación de la API: http://localhost:${PORT}/api-docs`);
        
        // Emitir evento de sistema cuando el servidor esté listo
        io?.emit('system:ready', { timestamp: new Date().toISOString() });
        
        resolve(server);
      });
      
      // Manejar errores del servidor
      server.on('error', (error: NodeJS.ErrnoException) => {
        if (error.syscall !== 'listen') {
          return reject(error);
        }
        
        switch (error.code) {
          case 'EACCES':
            logger.error(`El puerto ${PORT} requiere privilegios elevados`);
            process.exit(1);
            break;
          case 'EADDRINUSE':
            logger.error(`El puerto ${PORT} ya está en uso`);
            process.exit(1);
            break;
          default:
            reject(error);
        }
      });
    });
  } catch (error) {
    logger.error('Error al iniciar el servidor:', error);
    throw error;
  }
}

/**
 * Maneja el cierre elegante del servidor
 */
async function shutdown(server: HttpServer) {
  logger.info('Recibida señal de apagado. Cerrando servidor...');
  
  return new Promise<void>((resolve) => {
    // Cerrar servidor HTTP
    server.close(() => {
      logger.info('Servidor HTTP cerrado');
      
      // Cerrar conexiones de Socket.IO
      if (io) {
        io.close(() => {
          logger.info('Servidor Socket.IO cerrado');
          resolve();
        });
      } else {
        resolve();
      }
    });
    
    // Forzar cierre después de 10 segundos
    setTimeout(() => {
      logger.error('Forzando cierre por timeout...');
      process.exit(1);
    }, 10000);
  });
}

// Iniciar la aplicación si este archivo es el punto de entrada principal
if (require.main === module) {
  startServer()
    .then((server) => {
      // Manejar señales de terminación
      const shutdownHandler = () => {
        shutdown(server)
          .then(() => process.exit(0))
          .catch((error) => {
            logger.error('Error durante el cierre del servidor:', error);
            process.exit(1);
          });
      };
      
      process.on('SIGTERM', shutdownHandler);
      process.on('SIGINT', shutdownHandler);
      
      // Manejar excepciones no capturadas
      process.on('uncaughtException', (error) => {
        logger.error('Excepción no capturada:', error);
        shutdownHandler();
      });
      
      // Manejar promesas rechazadas no manejadas
      process.on('unhandledRejection', (reason, promise) => {
        logger.error('Promesa rechazada no manejada en:', promise, 'razón:', reason);
      });
    })
    .catch((error) => {
      logger.error('Error crítico al iniciar el servidor:', error);
      process.exit(1);
    });
}

export { startServer, shutdown, io };
