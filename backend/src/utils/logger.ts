import winston from 'winston';

// Configuración simple del logger para pruebas
const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  defaultMeta: { service: 'cloudcam-api' },
  transports: [
    new winston.transports.Console({
      format: winston.format.simple()
    })
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
