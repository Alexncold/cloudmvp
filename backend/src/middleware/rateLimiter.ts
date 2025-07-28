import rateLimit, { RateLimitRequestHandler } from 'express-rate-limit';
import { Request, Response, NextFunction } from 'express';
import { logger } from '../utils/logger';

// Default rate limit configuration
const defaultRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later.',
  handler: (req: Request, res: Response) => {
    logger.warn('Rate limit exceeded', {
      ip: req.ip,
      url: req.originalUrl,
      method: req.method
    });
    res.status(429).json({
      success: false,
      message: 'Too many requests, please try again later.'
    });
  },
  standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
  legacyHeaders: false, // Disable the `X-RateLimit-*` headers
});

// Rate limiter for authentication endpoints (more strict)
const authRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // Limit each IP to 10 requests per windowMs
  message: 'Too many login attempts, please try again later.',
  handler: (req: Request, res: Response) => {
    logger.warn('Auth rate limit exceeded', {
      ip: req.ip,
      url: req.originalUrl,
      method: req.method,
      email: req.body?.email || 'unknown'
    });
    res.status(429).json({
      success: false,
      message: 'Too many login attempts, please try again later.'
    });
  }
});

// Rate limiter for API endpoints (less strict)
const apiRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 200, // Limit each IP to 200 requests per windowMs
  message: 'Too many API requests, please try again later.'
});

// Rate limiter for public endpoints (even less strict)
const publicRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 500, // Limit each IP to 500 requests per windowMs
  message: 'Too many requests, please try again later.'
});

// Export rate limiters
const rateLimiter = {
  default: defaultRateLimit,
  auth: authRateLimit,
  api: apiRateLimit,
  public: publicRateLimit,
  rateLimit // The original rateLimit function
};

export default rateLimiter;
