import express, { Application, Request, Response, NextFunction } from 'express';
import cors from 'cors';
import helmet from 'helmet';
import passport from 'passport';
import session from 'express-session';
import cookieParser from 'cookie-parser';
import { rateLimit } from 'express-rate-limit';
import { logger } from './utils/logger';
import healthRouter from './health/health.routes';
import { ApiResponse } from './types';
import { configurePassport } from './services/passport';
import authRouter from './routes/auth';
import { authRateLimiter, registerRateLimiter, securityHeaders } from './middleware/security';
import { initEmailService } from './services/emailService';
import { requestLogger, errorLogger } from './middleware/requestLogger';

// Configure rate limiting
const apiLimiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS || '900000'), // 15 minutes by default
  max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS || '100'),
  standardHeaders: true,
  legacyHeaders: false,
  message: JSON.stringify({
    error: 'TOO_MANY_REQUESTS',
    message: 'Too many requests from this IP, please try again later',
  }),
});

// Configure session for OAuth
const sessionConfig: session.SessionOptions = {
  secret: process.env.SESSION_SECRET || 'your-session-secret',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax' as const,
  },
};

const createApp = async (): Promise<Application> => {
  const app = express();

  // Security middleware
  if (process.env.HELMET_ENABLED === 'true') {
    app.use(helmet());
  }

  // Request logging
  app.use(requestLogger);

  // CORS configuration
  const corsOptions = {
    origin: process.env.CORS_ORIGIN || '*',
    credentials: true,
    optionsSuccessStatus: 200, // For legacy browser support
  };
  
  app.use(cors(corsOptions));
  
  // Parse request bodies
  app.use(express.json({ limit: '10kb' }));
  app.use(express.urlencoded({ extended: true, limit: '10kb' }));
  app.use(cookieParser());
  
  // Session middleware
  app.use(session(sessionConfig));
  
  // Initialize Passport and session
  configurePassport(passport);
  app.use(passport.initialize());
  app.use(passport.session());
  
  // Security headers
  app.use(securityHeaders);
  
  // Apply rate limiting to all API routes
  app.use('/api', apiLimiter);
  
  // Initialize email service
  await initEmailService();

  // Logging de solicitudes
  app.use((req: Request, res: Response, next: NextFunction) => {
    const start = Date.now();
    
    res.on('finish', () => {
      const duration = Date.now() - start;
      logger.info(`${req.method} ${req.originalUrl} - ${res.statusCode} ${duration}ms`);
    });
    
    next();
  });

  // Health check route
  app.use('/health', healthRouter);
  
  // Authentication routes
  app.use('/api/auth', [
    // Apply specific rate limiters to auth routes
    (req: express.Request, res: express.Response, next: express.NextFunction) => {
      if (req.path === '/login') return authRateLimiter(req, res, next);
      if (req.path === '/register') return registerRateLimiter(req, res, next);
      next();
    },
    authRouter
  ]);

  // Root route
  app.get('/', (_req: Request, res: Response) => {
    const response: ApiResponse = {
      success: true,
      data: {
        name: 'CloudCam API',
        version: '1.0.0',
        environment: process.env.NODE_ENV || 'development',
      },
      timestamp: new Date().toISOString(),
    };
    res.json(response);
  });

  // 404 handler
  app.use((_req: Request, res: Response) => {
    const response: ApiResponse = {
      success: false,
      error: {
        code: 'NOT_FOUND',
        message: 'Endpoint not found',
      },
      timestamp: new Date().toISOString(),
    };
    res.status(404).json(response);
  });
  
  // Handle unhandled promise rejections
  process.on('unhandledRejection', (reason: Error) => {
    logger.error('Unhandled Rejection:', reason);
  });
  
  // Handle uncaught exceptions
  process.on('uncaughtException', (error: Error) => {
    logger.error('Uncaught Exception:', error);
    // In production, you might want to restart the process here
    // process.exit(1);
  });

  // Error logging middleware
  app.use(errorLogger);

  // Error handling middleware
  app.use((err: Error, req: Request, res: Response, next: NextFunction) => {
    // If headers were already sent, delegate to the default Express error handler
    if (res.headersSent) {
      return next(err);
    }

    // Log the error with request context
    logger.error('Error handler caught:', {
      message: err.message,
      stack: process.env.NODE_ENV === 'development' ? err.stack : undefined,
      path: req.path,
      method: req.method,
      params: req.params,
      query: req.query,
      body: req.body,
    });

    // Format the error response
    const statusCode = (err as any).statusCode || 500;
    const errorResponse: ApiResponse<null> = {
      success: false,
      error: {
        code: (err as any).code || 'INTERNAL_SERVER_ERROR',
        message: statusCode >= 500 ? 'An unexpected error occurred' : err.message,
        details: process.env.NODE_ENV === 'development' ? {
          stack: err.stack,
          ...(err as any).details,
        } : undefined,
      },
      data: null,
      timestamp: new Date().toISOString(),
    };

    res.status(statusCode).json(errorResponse);
  });

  // Handle JWT errors
  app.use((err: any, req: Request, res: Response, next: NextFunction) => {
    if (err.name === 'JsonWebTokenError' || err.name === 'TokenExpiredError') {
      return res.status(401).json({
        success: false,
        error: {
          code: 'INVALID_TOKEN',
          message: 'Invalid or expired authentication token',
        },
        timestamp: new Date().toISOString(),
      });
    }
    
    // Handle validation errors
    if (err.name === 'ValidationError') {
      return res.status(400).json({
        success: false,
        error: {
          code: 'VALIDATION_ERROR',
          message: 'Validation failed',
          details: err.details || err.message,
        },
        timestamp: new Date().toISOString(),
      });
    }
    
    // Handle rate limit errors
    if (err.status === 429) {
      return res.status(429).json({
        success: false,
        error: {
          code: 'RATE_LIMIT_EXCEEDED',
          message: 'Too many requests, please try again later',
          retryAfter: err.retryAfter,
        },
        timestamp: new Date().toISOString(),
      });
    }
    
    // Default error response
    const statusCode = err.statusCode || 500;
    const response: ApiResponse = {
      success: false,
      error: {
        code: err.code || 'INTERNAL_SERVER_ERROR',
        message: process.env.NODE_ENV === 'production' 
          ? 'An unexpected error occurred' 
          : err.message || 'Internal Server Error',
        details: process.env.NODE_ENV === 'development' ? err.stack : undefined,
      },
      timestamp: new Date().toISOString(),
    };
    
    res.status(statusCode).json(response);
  });

  return app;
};

export default createApp;
