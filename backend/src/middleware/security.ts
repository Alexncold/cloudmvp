import { Request, Response, NextFunction } from 'express';
import rateLimit from 'express-rate-limit';
import { validationResult, ValidationChain } from 'express-validator';
import jwt from 'jsonwebtoken';
import { logger } from '../utils/logger';

// Extend the Express Request type to include the user property
declare global {
  namespace Express {
    interface User {
      id: string;
      email: string;
      role: string;
      [key: string]: any;
    }
    interface Request {
      user?: User;
    }
  }
}

/**
 * Rate limiter for authentication endpoints
 * Limits to 5 requests per 15 minutes per IP
 */
export const authRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // Limit each IP to 5 requests per windowMs
  standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
  legacyHeaders: false, // Disable the `X-RateLimit-*` headers
  message: {
    error: 'Too many login attempts',
    message: 'Please try again after 15 minutes',
    retryAfter: 15 * 60 // 15 minutes in seconds
  },
  // Skip rate limiting for test environment
  skip: () => process.env.NODE_ENV === 'test',
  // Custom handler for rate limit exceeded
  handler: (req: Request, res: Response) => {
    logger.warn(`Rate limit exceeded for IP: ${req.ip} on path: ${req.path}`);
    res.status(429).json({
      error: 'Too many requests',
      message: 'Too many login attempts. Please try again later.'
    });
  }
});

/**
 * Rate limiter for registration endpoint
 * Limits to 3 registrations per hour per IP
 */
export const registerRateLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 3, // Limit each IP to 3 registration requests per hour
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: 'Too many registration attempts',
    message: 'You can only create 3 accounts per hour from the same IP',
    retryAfter: 60 * 60 // 1 hour in seconds
  },
  skip: () => process.env.NODE_ENV === 'test',
  handler: (req: Request, res: Response) => {
    logger.warn(`Registration rate limit exceeded for IP: ${req.ip}`);
    res.status(429).json({
      error: 'Too many registration attempts',
      message: 'Please try again in an hour or contact support'
    });
  }
});

/**
 * Global rate limiter for all other routes
 * Limits to 100 requests per 15 minutes per IP
 */
export const apiRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  standardHeaders: true,
  legacyHeaders: false,
  skip: () => process.env.NODE_ENV === 'test',
  handler: (req: Request, res: Response) => {
    logger.warn(`API rate limit exceeded for IP: ${req.ip} on path: ${req.path}`);
    res.status(429).json({
      error: 'Too many requests',
      message: 'Please try again later.'
    });
  }
});

/**
 * Middleware to validate request body using express-validator
 * @param validations Array of validation chains
 * @returns Middleware function
 */
export const validateRequest = (validations: ValidationChain[]) => {
  return async (req: Request, res: Response, next: NextFunction) => {
    await Promise.all(validations.map(validation => validation.run(req)));

    const errors = validationResult(req);
    if (errors.isEmpty()) {
      return next();
    }

    logger.warn('Validation failed', { 
      path: req.path, 
      errors: errors.array(),
      ip: req.ip,
      userAgent: req.get('user-agent')
    });

    res.status(400).json({
      error: 'Validation failed',
      message: 'Invalid request data',
      errors: errors.array()
    });
  };
};

/**
 * Middleware to check if user is authenticated
 * Requires a valid JWT token in the Authorization header
 */
export const requireAuth = (req: Request, res: Response, next: NextFunction) => {
  // Skip authentication for test environment
  if (process.env.NODE_ENV === 'test') {
    return next();
  }

  const authHeader = req.headers.authorization;
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    logger.warn('Unauthorized: No token provided', { path: req.path, ip: req.ip });
    return res.status(401).json({
      error: 'Unauthorized',
      message: 'No authentication token provided. Please log in.'
    });
  }

  const token = authHeader.split(' ')[1];
  
  try {
    // Verify JWT token
    const decoded = jwt.verify(token, process.env.JWT_SECRET!);
    
    // Attach user to request object
    req.user = decoded as Express.User;
    
    next();
  } catch (error: unknown) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    const errorName = error instanceof Error ? error.name : 'UnknownError';
    
    logger.warn('Invalid authentication token', { 
      error: errorMessage, 
      path: req.path, 
      ip: req.ip 
    });
    
    if (errorName === 'TokenExpiredError') {
      return res.status(401).json({
        error: 'Token expired',
        message: 'Your session has expired. Please log in again.'
      });
    }
    
    res.status(401).json({
      error: 'Invalid token',
      message: 'Invalid authentication token. Please log in again.'
    });
  }
};

/**
 * Middleware to check if user has admin role
 * Must be used after requireAuth middleware
 */
export const requireAdmin = (req: Request, res: Response, next: NextFunction) => {
  // Skip authorization for test environment
  if (process.env.NODE_ENV === 'test') {
    return next();
  }

  if (!req.user) {
    logger.error('requireAdmin used without requireAuth');
    return res.status(500).json({
      error: 'Server error',
      message: 'Authorization middleware misconfiguration'
    });
  }

  // Check if user has admin role
  if (req.user.role !== 'admin') {
    logger.warn('Forbidden: Admin access required', { 
      userId: req.user.id, 
      path: req.path 
    });
    return res.status(403).json({
      error: 'Forbidden',
      message: 'Admin privileges required to access this resource'
    });
  }

  next();
};

/**
 * Middleware to enable CORS with security headers
 */
export const securityHeaders = (req: Request, res: Response, next: NextFunction) => {
  // CORS headers
  res.header('Access-Control-Allow-Origin', process.env.FRONTEND_URL || '*');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
  res.header('Access-Control-Allow-Credentials', 'true');

  // Security headers
  res.header('X-Content-Type-Options', 'nosniff');
  res.header('X-Frame-Options', 'DENY');
  res.header('X-XSS-Protection', '1; mode=block');
  
  // Remove X-Powered-By header
  res.removeHeader('X-Powered-By');

  // Handle preflight requests
  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  next();
};

/**
 * Middleware to log all requests
 */
export const requestLogger = (req: Request, res: Response, next: NextFunction) => {
  // Skip logging for health checks
  if (req.path === '/health') {
    return next();
  }

  const start = Date.now();
  
  res.on('finish', () => {
    const duration = Date.now() - start;
    const logData = {
      method: req.method,
      path: req.path,
      status: res.statusCode,
      duration: `${duration}ms`,
      ip: req.ip,
      userAgent: req.get('user-agent'),
      userId: req.user?.id || 'anonymous'
    };

    // Log errors separately
    if (res.statusCode >= 400) {
      logger.error('Request error', logData);
    } else {
      logger.info('Request completed', logData);
    }
  });

  next();
};
