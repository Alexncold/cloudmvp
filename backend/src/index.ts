import 'dotenv/config';
import http from 'http';
import { logger } from './utils/logger';
import createApp from './app';

const PORT = process.env.PORT || 3001;
const NODE_ENV = process.env.NODE_ENV || 'development';

// Create Express application and HTTP server
let server: http.Server;

const initServer = async () => {
  try {
    const app = await createApp();
    server = http.createServer(app);
    
    // Start the server
    server.listen(PORT, () => {
      logger.info(`Server is running on port ${PORT} in ${NODE_ENV} mode`);
    });
    
    return server;
  } catch (error) {
    logger.error('Failed to initialize server:', error);
    process.exit(1);
  }
};

// Initialize the server
const serverPromise = initServer();

// Handle unhandled promise rejections
process.on('unhandledRejection', (reason: Error) => {
  logger.error('Unhandled Rejection at:', 'error', reason);
  // Consider whether you want to crash the process on unhandled rejections
  // process.exit(1);
});

// Handle uncaught exceptions
process.on('uncaughtException', (error: Error) => {
  logger.error('Uncaught Exception:', error);
  // Consider whether you want to crash the process on uncaught exceptions
  // process.exit(1);
});

// Start the server
const startServer = async () => {
  try {
    // Verify required environment variables
    const requiredEnvVars = [
      'JWT_SECRET',
      'AES_SECRET',
      'DATABASE_URL',
      'EMAIL_FROM',
      'FRONTEND_URL',
    ];

    const missingEnvVars = requiredEnvVars.filter(varName => !process.env[varName]);
    
    if (missingEnvVars.length > 0) {
      throw new Error(`Missing required environment variables: ${missingEnvVars.join(', ')}`);
    }

    // Start listening
    await new Promise<void>((resolve, reject) => {
      server.listen(PORT, () => {
        logger.info(`Server running in ${NODE_ENV} mode on port ${PORT}`);
        logger.info(`API Documentation: http://localhost:${PORT}/api-docs`);
        resolve();
      }).on('error', (error: Error) => {
        logger.error('Failed to start server:', error);
        reject(error);
      });
    });

  } catch (error) {
    logger.error('Failed to start server:', error);
    process.exit(1);
  }
};

// Handle graceful shutdown
const shutdown = async () => {
  logger.info('Shutting down server...');
  
  // Close the HTTP server
  server.close((error) => {
    if (error) {
      logger.error('Error closing server:', error);
      process.exit(1);
    }
    
    logger.info('Server closed');
    process.exit(0);
  });
};

// Handle termination signals
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);

// Start the application
startServer().catch((error) => {
  logger.error('Fatal error during application startup:', error);
  process.exit(1);
});
