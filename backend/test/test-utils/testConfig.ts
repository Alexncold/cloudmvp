import { config } from 'dotenv';
import path from 'path';
import { existsSync } from 'fs';

// Cargar variables de entorno específicas para pruebas
const envPath = path.resolve(__dirname, '../../.env.test');

// Verificar si el archivo .env.test existe
if (existsSync(envPath)) {
  config({ path: envPath });
} else {
  // Usar variables de entorno estándar si no existe .env.test
  config();
}

// Configuración de pruebas
const testConfig = {
  // Configuración de la base de datos de prueba
  db: {
    url: process.env.TEST_DATABASE_URL || process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production' 
      ? { rejectUnauthorized: true }
      : process.env.DB_SSL === 'true' 
        ? { rejectUnauthorized: false }
        : false,
  },
  
  // Configuración de autenticación para pruebas
  auth: {
    jwtSecret: process.env.JWT_SECRET || 'test-secret-key',
    jwtExpiration: '5m',
    refreshTokenExpiration: '7d',
    testUser: {
      email: process.env.TEST_USER_EMAIL || 'test@example.com',
      password: process.env.TEST_USER_PASSWORD || 'TestPassword123!',
      name: 'Test User',
    },
  },
  
  // Configuración del servidor
  server: {
    port: process.env.PORT ? parseInt(process.env.PORT, 10) : 3001,
    env: process.env.NODE_ENV || 'test',
    isProduction: process.env.NODE_ENV === 'production',
    isTest: process.env.NODE_ENV === 'test',
    isDevelopment: process.env.NODE_ENV === 'development',
  },
  
  // Configuración de logs
  logging: {
    level: process.env.LOG_LEVEL || 'error', // Nivel de log reducido para pruebas
    file: process.env.LOG_FILE || 'test.log',
    maxSize: '10m',
    maxFiles: '1d',
  },
  
  // Configuración de rate limiting para pruebas
  rateLimit: {
    windowMs: 15 * 60 * 1000, // 15 minutos
    max: 100, // Límite de solicitudes por ventana
    test: {
      // Configuración específica para pruebas de rate limiting
      maxAttempts: 5,
      windowMs: 60000, // 1 minuto
    },
  },
  
  // Configuración de seguridad
  security: {
    cors: {
      allowedOrigins: process.env.ALLOWED_ORIGINS
        ? process.env.ALLOWED_ORIGINS.split(',').map(origin => origin.trim())
        : ['http://localhost:3000'],
    },
    helmet: {
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          scriptSrc: ["'self'", "'unsafe-inline'"],
          styleSrc: ["'self'", "'unsafe-inline'"],
          imgSrc: ["'self'", 'data:'],
          connectSrc: ["'self'"],
        },
      },
    },
  },
  
  // Configuración de correo electrónico para pruebas
  email: {
    test: true, // No enviar correos reales durante las pruebas
    from: process.env.EMAIL_FROM || 'no-reply@test.com',
    transport: {
      host: process.env.EMAIL_HOST || 'smtp.test.com',
      port: process.env.EMAIL_PORT ? parseInt(process.env.EMAIL_PORT, 10) : 587,
      secure: process.env.EMAIL_SECURE === 'true',
      auth: {
        user: process.env.EMAIL_USER || 'user@test.com',
        pass: process.env.EMAIL_PASSWORD || 'password',
      },
    },
  },
  
  // Configuración de pruebas de integración
  integration: {
    baseUrl: process.env.TEST_BASE_URL || 'http://localhost:3001',
    apiPrefix: '/api',
    timeout: 10000, // 10 segundos de tiempo de espera para las pruebas
  },
  
  // Configuración de pruebas unitarias
  unit: {
    mockDb: true, // Usar base de datos simulada para pruebas unitarias
  },
};

// Validar configuración requerida
if (!testConfig.db.url) {
  throw new Error('TEST_DATABASE_URL o DATABASE_URL deben estar definidos en las variables de entorno');
}

if (!testConfig.auth.jwtSecret) {
  throw new Error('JWT_SECRET debe estar definido en las variables de entorno');
}

export default testConfig;
