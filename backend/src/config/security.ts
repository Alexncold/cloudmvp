import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import { RequestHandler } from 'express';

/**
 * Configuración de seguridad para la aplicación
 * Incluye configuración de Helmet y rate limiting
 */

export const securityConfig = {
  /**
   * Configuración de Helmet para cabeceras de seguridad HTTP
   */
  helmet: helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "'unsafe-inline'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", "data:", "https:"],
        connectSrc: ["'self'", "ws:", "wss:"],
        fontSrc: ["'self'", "https:", "data:"],
        objectSrc: ["'none'"],
        mediaSrc: ["'self'"],
        frameSrc: ["'self'"],
      },
    },
    hsts: {
      maxAge: 31536000, // 1 año
      includeSubDomains: true,
      preload: true
    },
    crossOriginEmbedderPolicy: true,
    crossOriginOpenerPolicy: true,
    crossOriginResourcePolicy: { policy: "same-site" },
    dnsPrefetchControl: { allow: true },
    frameguard: { action: 'deny' },
    hidePoweredBy: true,
    ieNoOpen: true,
    noSniff: true,
    xssFilter: true,
  }),

  /**
   * Rate limiting para la API general
   */
  apiLimiter: rateLimit({
    windowMs: parseInt(process.env.RATE_LIMIT_WINDOW || '900000'), // 15 minutos por defecto
    max: parseInt(process.env.RATE_LIMIT_MAX || '100'), // 100 peticiones por ventana
    message: {
      error: 'Límite de tasa excedido',
      message: 'Demasiadas peticiones desde esta IP, por favor inténtalo de nuevo más tarde',
      status: 429
    },
    standardHeaders: true,
    legacyHeaders: false,
    skip: (req) => {
      // Saltar rate limiting para ciertas rutas de salud o monitoreo
      return req.path === '/health' || req.path === '/metrics';
    }
  }),

  /**
   * Rate limiting específico para operaciones de descubrimiento
   */
  discoveryLimiter: rateLimit({
    windowMs: 5 * 60 * 1000, // 5 minutos
    max: 3, // Máximo 3 escaneos por IP cada 5 minutos
    message: {
      error: 'Límite de escaneos excedido',
      message: 'Demasiados escaneos iniciados, por favor espera 5 minutos',
      status: 429
    },
    standardHeaders: true,
    legacyHeaders: false,
    skip: (req) => {
      // Solo aplicar a rutas de descubrimiento
      return !req.path.startsWith('/api/discovery');
    }
  }),

  /**
   * Middleware para validar el rango de red permitido
   */
  validateNetworkRange: (allowedRanges: string[] = []): RequestHandler => {
    return (req, res, next) => {
      // Si no hay rangos definidos, permitir todo
      if (allowedRanges.length === 0) {
        return next();
      }

      // Obtener la IP del cliente
      const clientIp = req.ip || 
                      (req.headers['x-forwarded-for'] as string || '').split(',')[0] || 
                      req.socket.remoteAddress;

      // Verificar si la IP está en los rangos permitidos
      const ipRange = require('ip-range-check');
      const isAllowed = allowedRanges.some(range => ipRange(clientIp, range));

      if (!isAllowed) {
        return res.status(403).json({
          error: 'Acceso denegado',
          message: 'Tu dirección IP no está autorizada para realizar esta acción',
          ip: clientIp
        });
      }

      next();
    };
  },

  /**
   * Configuración de seguridad para WebSockets
   */
  wsSecurity: {
    // Tiempo máximo de inactividad en milisegundos
    clientTimeout: 60000,
    // Tamaño máximo de mensaje en bytes
    maxHttpBufferSize: 1e6, // 1MB
    // Número máximo de reconexiones
    maxReconnectionAttempts: 5
  }
};

export default securityConfig;
