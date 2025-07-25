import { logger } from './logger';

interface EnvVarValidation {
  name: string;
  required: boolean;
  type: 'string' | 'number' | 'boolean' | 'url' | 'email';
  pattern?: RegExp;
  defaultValue?: any;
}

const requiredEnvVars: EnvVarValidation[] = [
  // Base de datos
  { name: 'DATABASE_URL', required: true, type: 'string' },
  { name: 'DB_POOL_MAX', required: false, type: 'number', defaultValue: 20 },
  
  // Autenticación
  { name: 'JWT_SECRET', required: true, type: 'string' },
  { name: 'AES_SECRET', required: true, type: 'string' },
  
  // Google OAuth
  { name: 'GOOGLE_CLIENT_ID', required: true, type: 'string' },
  { name: 'GOOGLE_CLIENT_SECRET', required: true, type: 'string' },
  
  // SMTP
  { name: 'SMTP_HOST', required: false, type: 'string', defaultValue: 'smtp.gmail.com' },
  { name: 'SMTP_PORT', required: false, type: 'number', defaultValue: 587 },
  { name: 'SMTP_SECURE', required: false, type: 'boolean', defaultValue: false },
  { name: 'SMTP_USER', required: false, type: 'email' },
  { name: 'SMTP_PASS', required: false, type: 'string' },
  
  // Aplicación
  { name: 'NODE_ENV', required: true, type: 'string', pattern: /^(development|test|production)$/ },
  { name: 'PORT', required: false, type: 'number', defaultValue: 3001 },
  { name: 'FRONTEND_URL', required: true, type: 'url' },
  { name: 'API_BASE_URL', required: false, type: 'url', defaultValue: 'http://localhost:3001' },
];

const validators = {
  string: (value: string) => typeof value === 'string' && value.length > 0,
  number: (value: string) => !isNaN(Number(value)),
  boolean: (value: string) => value === 'true' || value === 'false',
  url: (value: string) => {
    try {
      new URL(value);
      return true;
    } catch {
      return false;
    }
  },
  email: (value: string) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)
};

export function validateEnv() {
  const missing: string[] = [];
  const invalid: Array<{name: string, reason: string}> = [];
  
  for (const envVar of requiredEnvVars) {
    const value = process.env[envVar.name];
    
    // Establecer valor por defecto si existe y no está definido
    if (value === undefined && envVar.defaultValue !== undefined) {
      process.env[envVar.name] = String(envVar.defaultValue);
      continue;
    }
    
    // Verificar variables requeridas
    if (envVar.required && !value) {
      missing.push(envVar.name);
      continue;
    }
    
    // Validar tipo
    if (value && envVar.type !== 'string') {
      const validator = validators[envVar.type];
      if (!validator(value)) {
        invalid.push({ 
          name: envVar.name, 
          reason: `Expected type ${envVar.type} but got '${value}'` 
        });
      }
    }
    
    // Validar patrón si existe
    if (value && envVar.pattern && !envVar.pattern.test(value)) {
      invalid.push({
        name: envVar.name,
        reason: `Value '${value}' does not match required pattern`
      });
    }
  }
  
  // Manejar errores
  if (missing.length > 0 || invalid.length > 0) {
    if (missing.length > 0) {
      logger.error('❌ Missing required environment variables:', missing);
    }
    
    if (invalid.length > 0) {
      logger.error('❌ Invalid environment variables:', 
        invalid.map(({name, reason}) => `${name}: ${reason}`).join('\n  ')
      );
    }
    
    process.exit(1);
  }
  
  // Validar configuraciones específicas por entorno
  if (process.env.NODE_ENV === 'production') {
    if (process.env.NODE_ENV === 'production' && 
        (!process.env.SMTP_USER || !process.env.SMTP_PASS)) {
      logger.warn('⚠️  SMTP credentials not configured. Email functionality will be disabled.');
    }
  }
  
  logger.info('✅ Environment variables validated successfully');
  
  // Mostrar configuración cargada (sin valores sensibles)
  if (process.env.NODE_ENV !== 'production') {
    const config = requiredEnvVars.reduce((acc, { name }) => {
      const value = process.env[name];
      acc[name] = name.includes('SECRET') || name.includes('PASS') || name.includes('KEY')
        ? '***HIDDEN***'
        : value;
      return acc;
    }, {} as Record<string, any>);
    
    logger.debug('Environment configuration:', config);
  }
}
