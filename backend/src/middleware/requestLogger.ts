import { Request, Response, NextFunction } from 'express';
import { logger } from '../utils/logger';

/**
 * Middleware to log all incoming requests
 */
export const requestLogger = (req: Request, res: Response, next: NextFunction) => {
  // Skip logging for health checks and static files
  if (req.path === '/health' || req.path.startsWith('/static/')) {
    return next();
  }

  const start = Date.now();
  const { method, originalUrl, ip, headers } = req;
  
  // Log the incoming request
  logger.info(`Request: ${method} ${originalUrl}`, {
    ip,
    userAgent: headers['user-agent'],
    contentType: headers['content-type'],
    authorization: headers['authorization'] ? '***' : undefined,
  });

  // Log request body for non-GET requests (except those with file uploads)
  if (method !== 'GET' && !req.is('multipart/form-data')) {
    const loggableBody = { ...req.body };
    
    // Redact sensitive fields
    if (loggableBody.password) loggableBody.password = '***';
    if (loggableBody.newPassword) loggableBody.newPassword = '***';
    if (loggableBody.currentPassword) loggableBody.currentPassword = '***';
    if (loggableBody.token) loggableBody.token = '***';
    
    logger.debug('Request body:', loggableBody);
  }

  // Log query parameters
  if (Object.keys(req.query).length > 0) {
    logger.debug('Query parameters:', req.query);
  }

  // Log response
  res.on('finish', () => {
    const duration = Date.now() - start;
    const { statusCode } = res;
    const contentLength = res.get('content-length') || 0;
    
    // Skip logging for 304 Not Modified responses
    if (statusCode === 304) return;

    const logData = {
      status: statusCode,
      duration: `${duration}ms`,
      contentLength,
      ip,
      userAgent: headers['user-agent'],
    };

    // Log at different levels based on status code
    if (statusCode >= 500) {
      logger.error(`Response: ${method} ${originalUrl}`, logData);
    } else if (statusCode >= 400) {
      logger.warn(`Response: ${method} ${originalUrl}`, logData);
    } else {
      logger.info(`Response: ${method} ${originalUrl}`, logData);
    }
  });

  next();
};

/**
 * Middleware to log unhandled errors
 */
export const errorLogger = (err: Error, req: Request, res: Response, next: NextFunction) => {
  logger.error('Unhandled error:', {
    message: err.message,
    stack: process.env.NODE_ENV === 'development' ? err.stack : undefined,
    path: req.path,
    method: req.method,
    ip: req.ip,
  });

  next(err);
};

export default {
  requestLogger,
  errorLogger,
};
