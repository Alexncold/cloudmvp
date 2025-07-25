import { Request, Response } from 'express';
import { logger } from '../utils/logger';

export const healthCheck = (_req: Request, res: Response) => {
  logger.info('Health check endpoint hit');
  
  const healthCheck = {
    status: 'UP',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    memoryUsage: process.memoryUsage(),
    nodeVersion: process.version,
    env: process.env.NODE_ENV || 'development',
  };

  try {
    res.status(200).json(healthCheck);
  } catch (error) {
    logger.error('Error in health check', { error });
    res.status(503).json({ 
      ...healthCheck, 
      status: 'DOWN',
      error: error instanceof Error ? error.message : 'Unknown error'
    });
  }
};

export const readinessCheck = async (_req: Request, res: Response) => {
  const checks = {
    database: false,
    redis: false,
    // Agregar más comprobaciones según sea necesario
  };

  // Verificar conexión a la base de datos (ejemplo con PostgreSQL)
  try {
    // Esto es un ejemplo - necesitarás implementar la lógica real de verificación
    // const dbCheck = await checkDatabaseConnection();
    // checks.database = dbCheck;
    checks.database = true; // Temporal para pruebas
  } catch (error) {
    logger.error('Database health check failed', { error });
  }

  // Verificar conexión a Redis
  try {
    // const redisCheck = await checkRedisConnection();
    // checks.redis = redisCheck;
    checks.redis = true; // Temporal para pruebas
  } catch (error) {
    logger.error('Redis health check failed', { error });
  }

  const isReady = Object.values(checks).every(Boolean);
  const status = isReady ? 200 : 503;
  
  res.status(status).json({
    status: isReady ? 'READY' : 'NOT_READY',
    timestamp: new Date().toISOString(),
    checks,
  });
};
