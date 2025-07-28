// Import types from Express
import type { Request, Response, NextFunction } from 'express';
import { verify } from 'jsonwebtoken';
import { promisify } from 'util';

// Local imports
import { verifyToken } from '../utils/jwt';
import { logger } from '../utils/logger';
import { AuthService } from '../services/auth.service';
import { TokenBlacklist } from '../services/token-blacklist.service';
import type { TokenPayload, User } from '../../../shared/types/auth';

// Extend Express Request type to include our custom properties
declare global {
  namespace Express {
    interface Request {
      user?: User;
      token?: string;
    }
  }
}

// Promisify verify for async/await
const verifyAsync = promisify(verify) as (
  token: string,
  secret: string
) => Promise<TokenPayload>;

/**
 * Rate limiting store (in-memory for now, consider Redis for production)
 */
const rateLimits = new Map<string, { count: number; resetTime: number }>();

/**
 * Check if a request should be rate limited
 * @param key Rate limit key (e.g., 'login:user@example.com' or 'ip:1.2.3.4')
 * @param limit Maximum number of requests allowed in the window
 * @param windowMs Time window in milliseconds
 * @returns Object with rate limit info
 */
const checkRateLimit = (
  key: string,
  limit: number,
  windowMs: number
): { allowed: boolean; remaining: number; resetTime: number } => {
  const now = Date.now();
  const rateLimit = rateLimits.get(key);

  // Initialize or reset rate limit window
  if (!rateLimit || now > rateLimit.resetTime) {
    rateLimits.set(key, {
      count: 1,
      resetTime: now + windowMs,
    });
    return { allowed: true, remaining: limit - 1, resetTime: now + windowMs };
  }

  // Check if rate limit exceeded
  if (rateLimit.count >= limit) {
    return { 
      allowed: false, 
      remaining: 0, 
      resetTime: rateLimit.resetTime 
    };
  }

  // Increment request count
  rateLimit.count++;
  rateLimits.set(key, rateLimit);

  return { 
    allowed: true, 
    remaining: limit - rateLimit.count, 
    resetTime: rateLimit.resetTime 
  };
};

/**
 * Authentication middleware with JWT verification and rate limiting
 */
export const authenticate = async (
  req: Request, 
  res: Response, 
  next: NextFunction
): Promise<void> => {
  try {
    // Get token from Authorization header or cookies
    const token = req.headers.authorization?.split(' ')[1] || req.cookies.accessToken;

    if (!token) {
      return res.status(401).json({ 
        success: false, 
        message: 'No authentication token provided',
        code: 'MISSING_TOKEN'
      });
    }

    // Check if token is blacklisted
    if (TokenBlacklist.isBlacklisted(token)) {
      logger.warn('Attempt to use blacklisted token', {
        ip: req.ip,
        userAgent: req.get('user-agent')
      });
      
      return res.status(401).json({
        success: false,
        message: 'Token has been revoked. Please log in again.',
        code: 'TOKEN_REVOKED'
      });
    }

    // Verify JWT token
    let payload: TokenPayload;
    try {
      payload = verifyToken(token, 'access') as TokenPayload;
      
      if (!payload || !payload.userId) {
        throw new Error('Invalid token payload');
      }
    } catch (error) {
      // If token is expired, provide a specific error code
      if (error instanceof Error && error.message.includes('jwt expired')) {
        return res.status(401).json({
          success: false,
          message: 'Session expired. Please refresh your token.',
          code: 'TOKEN_EXPIRED'
        });
      }
      
      // For any other JWT error
      return res.status(401).json({
        success: false,
        message: 'Invalid or malformed token',
        code: 'INVALID_TOKEN',
        error: error instanceof Error ? error.message : 'Unknown error'
      });
    }

    // Apply rate limiting for authenticated requests
    const rateLimitKey = `auth:${payload.userId}`;
    const rateLimit = checkRateLimit(rateLimitKey, 100, 3600000); // 100 requests/hour
    
    if (!rateLimit.allowed) {
      res.setHeader('Retry-After', Math.ceil((rateLimit.resetTime - Date.now()) / 1000));
      return res.status(429).json({
        success: false,
        message: 'Too many requests',
        code: 'RATE_LIMIT_EXCEEDED',
        retryAfter: Math.ceil((rateLimit.resetTime - Date.now()) / 1000)
      });
    }

    // Get user from database
    const user = await AuthService.getUserById(payload.userId);
    if (!user) {
      return res.status(401).json({
        success: false,
        message: 'User account not found',
        code: 'USER_NOT_FOUND'
      });
    }

    // Check if user account is active
    if (!user.isActive) {
      return res.status(403).json({
        success: false,
        message: 'Account is deactivated',
        code: 'ACCOUNT_DEACTIVATED'
      });
    }

    // Add user and token info to request object
    (req as any).user = user;
    (req as any).token = token;
    
    // Set rate limit headers
    res.setHeader('X-RateLimit-Limit', '100');
    res.setHeader('X-RateLimit-Remaining', rateLimit.remaining.toString());
    res.setHeader('X-RateLimit-Reset', Math.floor(rateLimit.resetTime / 1000).toString());
    
    next();
  } catch (error) {
    logger.error('Authentication error', {
      error: error instanceof Error ? error.message : 'Unknown error',
      stack: error instanceof Error ? error.stack : undefined,
      ip: req.ip,
      path: req.path,
      method: req.method
    });
    
    res.status(500).json({
      success: false,
      message: 'An unexpected error occurred during authentication',
      code: 'AUTH_ERROR'
    });
  }
};

/**
 * Role-based authorization middleware
 * @param roles Array of allowed roles (empty array allows any authenticated user)
 */
export const authorize = (roles: string[] = []) => {
  return (req: Request, res: Response, next: NextFunction): void => {
    try {
      const user = (req as any).user;
      
      if (!user) {
        return res.status(401).json({ 
          success: false, 
          message: 'Authentication required',
          code: 'UNAUTHORIZED'
        });
      }

      // If no roles specified, any authenticated user can access
      if (roles.length === 0) {
        return next();
      }

      // Check if user has any of the required roles
      const hasRole = roles.some(role => user.role === role);
      
      if (!hasRole) {
        logger.warn('Unauthorized access attempt', {
          userId: user.id,
          requiredRoles: roles,
          userRole: user.role,
          path: req.path,
          method: req.method
        });
        
        return res.status(403).json({
          success: false,
          message: 'Insufficient permissions',
          code: 'FORBIDDEN',
          requiredRoles: roles
        });
      }

      next();
    } catch (error) {
      logger.error('Authorization error', {
        error: error instanceof Error ? error.message : 'Unknown error',
        stack: error instanceof Error ? error.stack : undefined,
        path: req.path,
        method: req.method
      });
      
      res.status(500).json({
        success: false,
        message: 'An error occurred while checking permissions',
        code: 'AUTHORIZATION_ERROR'
      });
    }
  };
};

/**
 * Middleware to ensure the authenticated user is the same as the requested user
 * or has admin privileges
 */
export const authorizeSelfOrAdmin = (idParam = 'id') => {
  return (req: Request, res: Response, next: NextFunction): void => {
    try {
      const user = (req as any).user;
      const requestedId = req.params[idParam];
      
      if (!user) {
        return res.status(401).json({ 
          success: false, 
          message: 'Authentication required',
          code: 'UNAUTHORIZED'
        });
      }
      
      // Allow access if user is admin or owns the resource
      if (user.role === 'admin' || user.id === requestedId) {
        return next();
      }
      
      logger.warn('Unauthorized access attempt to user resource', {
        userId: user.id,
        requestedUserId: requestedId,
        path: req.path,
        method: req.method
      });
      
      res.status(403).json({
        success: false,
        message: 'You do not have permission to access this resource',
        code: 'FORBIDDEN'
      });
      
    } catch (error) {
      logger.error('Self/Admin authorization error', {
        error: error instanceof Error ? error.message : 'Unknown error',
        stack: error instanceof Error ? error.stack : undefined,
        path: req.path,
        method: req.method
      });
      
      res.status(500).json({
        success: false,
        message: 'An error occurred while checking permissions',
        code: 'AUTHORIZATION_ERROR'
      });
    }
  };
};

/**
 * Middleware para manejar errores de autenticación
 */
export const errorHandler = (
  err: Error,
  _req: Request,
  res: Response,
  _next: NextFunction
): void => {
  logger.error('Error en el middleware de autenticación:', err);
  
  res.status(500).json({
    success: false,
    message: 'Error interno del servidor',
    error: process.env.NODE_ENV === 'development' ? err.message : undefined
  });
};
