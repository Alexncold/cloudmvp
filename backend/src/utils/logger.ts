import winston from 'winston';

const { combine, timestamp, printf, colorize, json } = winston.format;

// Formato personalizado para los logs
const logFormat = printf(({ level, message, timestamp, ...meta }) => {
  return `${timestamp} [${level.toUpperCase()}] ${message} ${
    Object.keys(meta).length ? JSON.stringify(meta, null, 2) : ''
  }`;
});

// Configuración del logger
const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: combine(
    timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
    winston.format.errors({ stack: true }),
    process.env.NODE_ENV === 'production' ? json() : combine(colorize(), logFormat)
  ),
  defaultMeta: { service: 'cloudcam-api' },
  transports: [
    new winston.transports.Console({
      format: combine(
        colorize(),
        logFormat
      )
    }),
    // En producción, también podríamos agregar transporte a archivos
    // new winston.transports.File({ filename: 'logs/error.log', level: 'error' }),
    // new winston.transports.File({ filename: 'logs/combined.log' })
  ]
});

// Interceptar console.log, error, etc. para usar winston
if (process.env.NODE_ENV !== 'development') {
  console.log = (...args) => logger.info(args.join(' '));
  console.info = (...args) => logger.info(args.join(' '));
  console.warn = (...args) => logger.warn(args.join(' '));
  console.error = (...args) => logger.error(args.join(' '));
  console.debug = (...args) => logger.debug(args.join(' '));
}

export { logger };
