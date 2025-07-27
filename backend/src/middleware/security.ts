import { Request, Response, NextFunction } from 'express';
import rateLimit from 'express-rate-limit';
import { validationResult, ValidationChain } from 'express-validator';
import { verifyToken, TokenExpiredError, JsonWebTokenError } from '../utils/jwt';
import { logger } from '../utils/logger';
import { db } from '../services/db';
import type { TokenPayload } from '../types/auth';

// Import LocalUser type from auth types
import type { LocalUser } from '../types/auth';

// Type for the user object we'll attach to the request
type RequestUser = Omit<LocalUser, 'password_hash' | 'refresh_token_hash'> & {
  role?: string;
};

// Extend the Express Request and User types
declare global {
  namespace Express {
    // Define a base user interface without sensitive fields
    interface BaseUser {
      id: string;
      email: string;
      name: string;
      is_verified: boolean;
      created_at: Date;
      updated_at: Date;
      verification_token?: string | null;
      verification_token_expires?: Date | null;
      reset_password_token?: string | null;
      reset_password_expires?: Date | null;
      role?: string;
    }
    
    // Extend the User interface
    interface User extends BaseUser {
      type?: 'access' | 'refresh';
    }
    
    // Extend the Request interface to include the user property
    interface Request {
      user?: User;
      token?: string;
      id?: string;
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
export const requireAuth = async (req: Request, res: Response, next: NextFunction) => {
  try {
    // Skip authentication for test environment
    if (process.env.NODE_ENV === 'test') {
      return next();
    }

    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      logger.warn('Unauthorized: No token provided', { 
        path: req.path, 
        ip: req.ip,
        headers: req.headers,
        method: req.method
      });
      
      return res.status(401).json({
        error: 'Unauthorized',
        code: 'MISSING_AUTH_TOKEN',
        message: 'No authentication token provided. Please log in.'
      });
    }

    const token = authHeader.split(' ')[1];
    
    try {
      // Verify JWT token using our centralized token verification
      const decoded = verifyToken(token, 'access');
      
      // Get fresh user data from database
      interface UserRow {
        id: string;
        email: string;
        name: string;
        password_hash: string;
        is_verified: boolean;
        role?: string;
        created_at: Date;
        updated_at: Date;
        verification_token?: string | null;
        verification_token_expires?: Date | null;
        reset_password_token?: string | null;
        reset_password_expires?: Date | null;
        refresh_token_hash?: string | null;
      }

      // Query the database and properly type the result
      const userResult = await db.query(
        'SELECT * FROM users WHERE id = $1',
        [decoded.userId]
      ) as unknown as { rows: UserRow[] };
      
      if (userResult.rows.length === 0) {
        logger.warn('User not found for valid token', { 
          userId: decoded.userId,
          ip: req.ip 
        });
        
        return res.status(401).json({
          error: 'Unauthorized',
          code: 'USER_NOT_FOUND',
          message: 'User account not found.'
        });
      }
      
      const user = userResult.rows[0];
      
      // Check if user is active/verified if required
      if (user.is_verified === false) {
        return res.status(403).json({
          error: 'Forbidden',
          code: 'ACCOUNT_NOT_VERIFIED',
          message: 'Please verify your email address before proceeding.'
        });
      }
      
      // Attach user to request object (excluding sensitive fields)
      const { password_hash, refresh_token_hash, ...userData } = user;
      // Create a properly typed user object for the request
      const safeUser: RequestUser = {
        id: user.id,
        email: user.email,
        name: user.name,
        is_verified: user.is_verified,
        created_at: user.created_at,
        updated_at: user.updated_at,
        verification_token: user.verification_token,
        verification_token_expires: user.verification_token_expires,
        reset_password_token: user.reset_password_token,
        reset_password_expires: user.reset_password_expires,
        role: user.role || 'user'
      };
      
      // Assign to req.user with type assertion
      (req as any).user = safeUser;
      
      // Add token to request for rate limiting/auditing
      (req as any).token = token;
      
      return next();
      
    } catch (error) {
      // Handle specific JWT errors
      if (error instanceof TokenExpiredError) {
        logger.warn('Expired authentication token', { 
          path: req.path,
          ip: req.ip,
          error: error.message
        });
        
        return res.status(401).json({
          error: 'Token expired',
          code: 'TOKEN_EXPIRED',
          message: 'Your session has expired. Please log in again.'
        });
      }
      
      if (error instanceof JsonWebTokenError) {
        logger.warn('Invalid authentication token', { 
          path: req.path,
          ip: req.ip,
          error: error.message
        });
        
        return res.status(401).json({
          error: 'Invalid token',
          code: 'INVALID_TOKEN',
          message: 'Invalid authentication token. Please log in again.'
        });
      }
      
      // Re-throw unexpected errors to be handled by the global error handler
      throw error;
    }
  } catch (error) {
    logger.error('Authentication error', {
      error: error instanceof Error ? error.message : 'Unknown error',
      path: req.path,
      ip: req.ip,
      stack: error instanceof Error ? error.stack : undefined
    });
    
    // Use next(error) to pass to the global error handler
    next(new Error('Authentication failed'));
  }
}

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
  const user = req.user as LocalUser & { role?: string };
  if (user.role !== 'admin') {
    logger.warn('Forbidden: Admin access required', { 
      userId: user.id, 
      path: req.path 
    });
    return res.status(403).json({
      error: 'Forbidden',
      message: 'Admin privileges required to access this resource'
    });
  }

  next();
};

// Lista de orígenes permitidos (CORS)
const allowedOrigins = (process.env.ALLOWED_ORIGINS || '')
  .split(',')
  .map(origin => origin.trim())
  .filter(origin => {
    // Validar el formato de los orígenes
    if (!origin) return false;
    try {
      const url = new URL(origin);
      return url.protocol === 'http:' || url.protocol === 'https:';
    } catch {
      logger.warn(`Invalid ALLOWED_ORIGINS value: ${origin}`);
      return false;
    }
  });

// Orígenes permitidos en desarrollo
const developmentOrigins = [
  'http://localhost:3000',
  'http://127.0.0.1:3000',
  'http://localhost:3001',
  'http://127.0.0.1:3001'
];

// Orígenes permitidos en producción (ajusta según sea necesario)
const productionOrigins = [
  'https://tudominio.com',
  'https://www.tudominio.com'
];

// Orígenes finales basados en el entorno
const finalAllowedOrigins = process.env.NODE_ENV === 'production'
  ? [...productionOrigins, ...allowedOrigins]
  : [...developmentOrigins, ...allowedOrigins];

// Configuración de directivas de seguridad de contenido (CSP)
const cspDirectives = {
  defaultSrc: ["'none'"], // Por defecto, denegar todo
  scriptSrc: [
    "'self'",
    ...(process.env.NODE_ENV === 'development' ? [
      "'unsafe-inline'",
      "'unsafe-eval'"
    ] : []),
    'https://cdn.jsdelivr.net',
    'https://www.googletagmanager.com',
    'https://www.google-analytics.com'
  ],
  styleSrc: [
    "'self'",
    "'unsafe-inline'",
    'https://fonts.googleapis.com',
    'https://cdn.jsdelivr.net'
  ],
  imgSrc: [
    "'self'",
    'data:',
    'https:',
    'https://www.google-analytics.com',
    'https://www.googletagmanager.com'
  ],
  fontSrc: [
    "'self'",
    'data:',
    'https://fonts.gstatic.com',
    'https://cdn.jsdelivr.net'
  ],
  connectSrc: [
    "'self'",
    ...finalAllowedOrigins,
    'https://www.google-analytics.com',
    'https://region1.google-analytics.com',
    'https://analytics.google.com',
    ...(process.env.API_BASE_URL ? [process.env.API_BASE_URL] : []),
    ...(process.env.NODE_ENV === 'development' ? [
      'ws://localhost:*',
      'http://localhost:*',
      'ws://127.0.0.1:*',
      'http://127.0.0.1:*'
    ] : [])
  ],
  frameAncestors: ["'none'"],
  frameSrc: [
    "'self'",
    'https://www.google.com',
    'https://www.youtube.com'
  ],
  formAction: ["'self'"],
  baseUri: ["'self'"],
  objectSrc: ["'none'"],
  scriptSrcAttr: ["'unsafe-inline'"],
  upgradeInsecureRequests: process.env.NODE_ENV === 'production' ? [] : null,
  blockAllMixedContent: true
};

/**
 * Genera el header CSP a partir de las directivas
 */
const generateCSP = (): string => {
  try {
    return Object.entries(cspDirectives)
      .filter(([_, value]) => value !== null && value !== undefined)
      .map(([key, value]) => {
        if (Array.isArray(value)) {
          const values = Array.from(new Set(value)); // Eliminar duplicados
          return `${key} ${values.join(' ')}`;
        }
        return `${key} ${value}`;
      })
      .join('; ')
      .replace(/\s+/g, ' ') // Eliminar espacios múltiples
      .trim();
  } catch (error) {
    logger.error('Error generating CSP header', {
      error: error instanceof Error ? error.message : 'Unknown error'
    });
    
    // Política de seguridad estricta por defecto en caso de error
    return "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self';"
  }
};

/**
 * Middleware para habilitar CORS con encabezados de seguridad mejorados
 */
export const securityHeaders = (req: Request, res: Response, next: NextFunction) => {
  try {
    const origin = req.headers.origin || '';
    const isAllowedOrigin = finalAllowedOrigins.includes(origin) || 
      (process.env.NODE_ENV === 'development' && origin.startsWith('http://localhost:'));
    
    // Configuración de CORS
    if (isAllowedOrigin) {
      res.header('Access-Control-Allow-Origin', origin);
      res.header('Access-Control-Allow-Credentials', 'true');
      res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, OPTIONS');
      res.header('Access-Control-Allow-Headers', [
        'Origin',
        'X-Requested-With',
        'Content-Type',
        'Accept',
        'Authorization',
        'X-Requested-With',
        'X-Request-ID',
        'X-CSRF-Token'
      ].join(', '));
      
      // Exponer headers personalizados si es necesario
      res.header('Access-Control-Expose-Headers', [
        'Content-Length',
        'Content-Range',
        'X-Total-Count',
        'X-Request-ID'
      ].join(', '));
      
      // Manejar preflight requests
      if (req.method === 'OPTIONS') {
        res.header('Access-Control-Max-Age', '86400'); // 24 horas
        return res.status(204).end();
      }
    } else if (origin) {
      // Registrar intentos de acceso desde orígenes no permitidos
      logger.warn('CORS: Origin not allowed', {
        origin,
        method: req.method,
        path: req.path,
        ip: req.ip
      });
      
      if (process.env.NODE_ENV === 'production') {
        // En producción, no permitir el acceso
        return res.status(403).json({
          error: 'Forbidden',
          message: 'Origin not allowed'
        });
      }
    }

    // Headers de seguridad
    const securityHeadersConfig = {
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'X-XSS-Protection': '1; mode=block',
      'Referrer-Policy': 'strict-origin-when-cross-origin',
      'X-Permitted-Cross-Domain-Policies': 'none',
      'X-DNS-Prefetch-Control': 'off',
      'Cross-Origin-Resource-Policy': 'same-site',
      'Cross-Origin-Opener-Policy': 'same-origin',
      'Cross-Origin-Embedder-Policy': 'require-corp',
      'Cache-Control': 'no-store, max-age=0',
      'Pragma': 'no-cache',
      'Expires': '0',
      'X-Request-ID': req.id || crypto.randomUUID()
    };
    
    // Aplicar headers de seguridad
    Object.entries(securityHeadersConfig).forEach(([key, value]) => {
      if (value !== null) {
        res.header(key, value);
      }
    });
    
    // HSTS - Solo en producción y sobre HTTPS
    if (process.env.NODE_ENV === 'production' && req.secure) {
      res.header('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload');
    }
    
    // CSP - Solo establecer si no es una solicitud de datos (API)
    if (!req.path.startsWith('/api/') || req.path.endsWith('.json')) {
      res.header('Content-Security-Policy', generateCSP());
    }
    
    // Permissions Policy (anteriormente Feature Policy)
    res.header('Permissions-Policy', [
      'camera=()',
      'geolocation=()',
      'microphone=()',
      'payment=()',
      'fullscreen=()',
      'display-capture=()',
      'web-share=()',
      'autoplay=()',
      'sync-xhr=()',
      'usb=()',
      'bluetooth=()',
      'battery=()',
      'accelerometer=()',
      'gyroscope=()',
      'magnetometer=()',
      'midi=()',
      'picture-in-picture=()',
      'publickey-credentials-get=()',
      'screen-wake-lock=()',
      'serial=()',
      'xr-spatial-tracking=()'
    ].join(', '));
    
    // Seguridad adicional para cookies
    if (req.cookies) {
      // Asegurar que las cookies estén configuradas correctamente
      const cookieOptions = {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax' as const,
        path: '/',
        maxAge: 7 * 24 * 60 * 60 * 1000, // 7 días
        domain: process.env.COOKIE_DOMAIN || undefined
      };
      
      // Aplicar opciones a las cookies existentes
      Object.keys(req.cookies).forEach(cookieName => {
        if (cookieName.startsWith('_') || ['token', 'session'].some(k => cookieName.includes(k))) {
          res.cookie(cookieName, req.cookies[cookieName], cookieOptions);
        }
      });
    }
    
    next();
  } catch (error) {
    logger.error('Error in securityHeaders middleware', {
      error: error instanceof Error ? error.message : 'Unknown error',
      path: req.path,
      ip: req.ip
    });
    
    // Continuar con la solicitud incluso si hay un error en el middleware de seguridad
    next();
  }
};

/**
 * Middleware to log all requests
 */
export const requestLogger = (req: Request, res: Response, next: NextFunction) => {
  const start = Date.now();
  const { method, originalUrl, ip, headers } = req;
  const requestId = req.id || crypto.randomUUID();
  
  // Agregar el ID de solicitud al objeto de solicitud para su uso posterior
  req.id = requestId;
  
  // Rutas que deben omitirse del registro
  const ignoredPaths = [
    '/health',
    '/favicon.ico',
    '/robots.txt',
    '/metrics',
    '/status'
  ];
  
  // Omitir el registro de rutas específicas
  if (ignoredPaths.some(path => originalUrl.startsWith(path))) {
    return next();
  }
  
  // Type for sanitized object with string index signature
  interface SanitizedObject {
    [key: string]: unknown;
  }
  
  // Type guard to check if value is a record
  const isRecord = (value: unknown): value is Record<string, unknown> => {
    return value !== null && typeof value === 'object' && !Array.isArray(value);
  };
  
  // Sanitize sensitive data from objects
  function sanitize(obj: unknown): unknown {
    // Handle non-object values
    if (!isRecord(obj)) return obj;
    
    const sensitiveKeys = [
      'password',
      'token',
      'apiKey',
      'api_key',
      'secret',
      'access_token',
      'refresh_token',
      'authorization',
      'card_number',
      'credit_card',
      'creditCard',
      'cvv',
      'ssn',
      'social_security',
      'socialSecurity',
      'passport',
      'driving_license',
      'drivingLicense'
    ] as const;
    
    // Create a new object to avoid mutating the original
    const result: SanitizedObject = {};
    
    // Process each key-value pair in the object
    for (const [key, value] of Object.entries(obj)) {
      const lowerKey = key.toLowerCase();
      
      // Check if the key contains any sensitive terms
      if (sensitiveKeys.some(sk => lowerKey.includes(sk))) {
        result[key] = '***REDACTED***';
      } 
      // Recursively sanitize nested objects
      else if (isRecord(value)) {
        result[key] = sanitize(value);
      } 
      // Handle arrays (sanitize each item if it's an object)
      else if (Array.isArray(value)) {
        result[key] = value.map(item => 
          isRecord(item) ? sanitize(item) : item
        );
      } 
      // Primitive values can be copied as-is
      else {
        result[key] = value;
      }
    }
    
    return result;
  };
  
  // Registrar la solicitud
  const logRequest = () => {
    const requestData = {
      requestId,
      method,
      url: originalUrl,
      ip,
      userAgent: headers['user-agent'],
      referrer: headers['referer'] || headers['referrer'],
      host: headers['host'],
      protocol: req.protocol,
      body: req.body ? sanitize(req.body) : undefined,
      query: Object.keys(req.query).length > 0 ? sanitize(req.query) : undefined,
      params: Object.keys(req.params).length > 0 ? sanitize(req.params) : undefined,
      headers: sanitize(headers as Record<string, any>),
      timestamp: new Date().toISOString()
    };
    
    // No registrar el cuerpo de las solicitudes de carga de archivos grandes
    if (headers['content-length'] && parseInt(headers['content-length']) > 1024 * 1024) {
      delete requestData.body;
      requestData.body = '***LARGE PAYLOAD***';
    }
    
    logger.info(`Request: ${method} ${originalUrl}`, requestData);
  };
  
  // Registrar la respuesta
  const logResponse = () => {
    const duration = Date.now() - start;
    const { statusCode } = res;
    
    const responseData = {
      requestId,
      method,
      url: originalUrl,
      statusCode,
      duration: `${duration}ms`,
      ip,
      timestamp: new Date().toISOString(),
      responseHeaders: sanitize(res.getHeaders())
    };
    
    // Clasificar el nivel de log según el código de estado
    if (statusCode >= 500) {
      logger.error(`Response: ${method} ${originalUrl} ${statusCode}`, responseData);
    } else if (statusCode >= 400) {
      logger.warn(`Response: ${method} ${originalUrl} ${statusCode}`, responseData);
    } else if (process.env.NODE_ENV === 'development' || process.env.DEBUG === 'true') {
      // Solo registrar respuestas exitosas en desarrollo o si el modo debug está activado
      logger.info(`Response: ${method} ${originalUrl} ${statusCode}`, responseData);
    }
  };
  
  // Registrar la solicitud después de que se complete el procesamiento del cuerpo
  if (req.body && Object.keys(req.body).length > 0) {
    logRequest();
  } else {
    // Si no hay cuerpo, registrar de inmediato
    logRequest();
    
    // Para solicitudes con cuerpo, configurar un manejador para registrar después de que se complete el análisis del cuerpo
    const originalJson = res.json;
    res.json = function(body) {
      // Registrar la respuesta antes de enviarla
      logResponse();
      return originalJson.call(this, body);
    };
  }
  
  // Registrar cuando se complete la respuesta
  res.on('finish', logResponse);
  
  // Manejar errores
  res.on('error', (error) => {
    logger.error('Response error', {
      requestId,
      method,
      url: originalUrl,
      error: error instanceof Error ? error.message : 'Unknown error',
      stack: error instanceof Error ? error.stack : undefined,
      timestamp: new Date().toISOString()
    });
  });
  
  next();
};
