import { body, validationResult, ValidationChain, ValidationError } from 'express-validator';
import { Request, Response, NextFunction } from 'express';
import { logger } from '../utils/logger';
import xss from 'xss-clean';
import mongoSanitize from 'express-mongo-sanitize';

// Opciones de saneamiento para express-mongo-sanitize
const sanitizeOptions = {
  replaceWith: '_',  // Reemplazar caracteres prohibidos con un guión bajo
  onSanitize: ({ key, req }) => {
    logger.warn('Sanitized request data', {
      key,
      value: req.body[key],
      path: req.path,
      ip: req.ip
    });
  }
};

/**
 * Middleware para prevenir ataques XSS
 */
export const xssProtection = (req: Request, res: Response, next: NextFunction) => {
  // Sanitizar el body
  if (req.body) {
    req.body = Object.entries(req.body).reduce((acc, [key, value]) => {
      if (typeof value === 'string') {
        acc[key] = xss(value);
      } else {
        acc[key] = value;
      }
      return acc;
    }, {} as Record<string, any>);
  }
  
  // Sanitizar query params
  if (req.query) {
    req.query = Object.entries(req.query).reduce((acc, [key, value]) => {
      if (typeof value === 'string') {
        acc[key] = xss(value);
      } else if (Array.isArray(value)) {
        acc[key] = value.map(v => typeof v === 'string' ? xss(v) : v);
      } else {
        acc[key] = value;
      }
      return acc;
    }, {} as Record<string, any>);
  }
  
  next();
};

/**
 * Middleware para prevenir inyección NoSQL
 */
export const noSqlInjectionProtection = [
  // Elimina claves que comiencen con $ (operadores de consulta de MongoDB)
  mongoSanitize(sanitizeOptions),
  
  // Sanitiza los parámetros de consulta
  (req: Request, res: Response, next: NextFunction) => {
    // Sanitizar los parámetros de ruta
    if (req.params) {
      req.params = Object.entries(req.params).reduce((acc, [key, value]) => {
        if (typeof value === 'string') {
          acc[key] = value.replace(/[${}]/g, '');
        } else {
          acc[key] = value;
        }
        return acc;
      }, {} as Record<string, any>);
    }
    
    next();
  }
];

/**
 * Reglas de validación comunes
 */
export const validationRules = {
  // Validación de email
  email: () => body('email')
    .trim()
    .notEmpty().withMessage('El correo electrónico es requerido')
    .isEmail().withMessage('Correo electrónico inválido')
    .normalizeEmail(),
  
  // Validación de contraseña
  password: () => body('password')
    .trim()
    .notEmpty().withMessage('La contraseña es requerida')
    .isLength({ min: 8 }).withMessage('La contraseña debe tener al menos 8 caracteres')
    .matches(/[A-Z]/).withMessage('La contraseña debe contener al menos una letra mayúscula')
    .matches(/[a-z]/).withMessage('La contraseña debe contener al menos una letra minúscula')
    .matches(/[0-9]/).withMessage('La contraseña debe contener al menos un número')
    .matches(/[^A-Za-z0-9]/).withMessage('La contraseña debe contener al menos un carácter especial'),
  
  // Validación de nombre
  name: (field = 'name') => body(field)
    .trim()
    .notEmpty().withMessage('El nombre es requerido')
    .isLength({ min: 2, max: 50 }).withMessage('El nombre debe tener entre 2 y 50 caracteres')
    .matches(/^[a-zA-ZáéíóúÁÉÍÓÚñÑ\s'-]+$/).withMessage('El nombre solo puede contener letras y espacios'),
  
  // Validación de ID de MongoDB
  mongoId: (field: string) => body(field)
    .trim()
    .notEmpty().withMessage('El ID es requerido')
    .matches(/^[0-9a-fA-F]{24}$/).withMessage('ID inválido'),
  
  // Validación de URL
  url: (field: string) => body(field)
    .trim()
    .optional({ checkFalsy: true })
    .isURL().withMessage('URL inválida'),
  
  // Validación de número de teléfono
  phone: (field = 'phone') => body(field)
    .trim()
    .optional({ checkFalsy: true })
    .matches(/^[0-9+\s-]{10,20}$/).withMessage('Número de teléfono inválido')
};

/**
 * Middleware para manejar errores de validación
 */
export const validateRequest = (validations: ValidationChain[]) => {
  return async (req: Request, res: Response, next: NextFunction) => {
    // Ejecutar todas las validaciones
    await Promise.all(validations.map(validation => validation.run(req)));

    // Obtener los errores de validación
    const errors = validationResult(req);
    
    // Si no hay errores, continuar
    if (errors.isEmpty()) {
      return next();
    }

    // Registrar el error
    const errorMessages = errors.array().map((err: ValidationError) => ({
      field: err.param,
      message: err.msg,
      value: err.value
    }));
    
    logger.warn('Validation failed', { 
      path: req.path, 
      errors: errorMessages,
      ip: req.ip,
      userAgent: req.get('user-agent')
    });

    // Devolver los errores
    res.status(400).json({
      success: false,
      error: 'Validation failed',
      message: 'Error de validación en los datos proporcionados',
      errors: errorMessages
    });
  };
};

/**
 * Middleware para validar y sanear parámetros de consulta
 */
export const validateQueryParams = (validations: ValidationChain[]) => {
  return async (req: Request, res: Response, next: NextFunction) => {
    // Mover los parámetros de consulta al body para la validación
    req.body = { ...req.body, ...req.query };
    
    // Ejecutar validaciones
    await Promise.all(validations.map(validation => validation.run(req)));
    
    // Obtener errores
    const errors = validationResult(req);
    
    if (!errors.isEmpty()) {
      const errorMessages = errors.array().map((err: ValidationError) => ({
        param: err.param,
        message: err.msg,
        value: err.value
      }));
      
      return res.status(400).json({
        success: false,
        error: 'Invalid query parameters',
        message: 'Parámetros de consulta inválidos',
        errors: errorMessages
      });
    }
    
    next();
  };
};

/**
 * Middleware para validar y sanear parámetros de ruta
 */
export const validateRouteParams = (validations: ValidationChain[]) => {
  return async (req: Request, res: Response, next: NextFunction) => {
    // Mover los parámetros de ruta al body para la validación
    req.body = { ...req.body, ...req.params };
    
    // Ejecutar validaciones
    await Promise.all(validations.map(validation => validation.run(req)));
    
    // Obtener errores
    const errors = validationResult(req);
    
    if (!errors.isEmpty()) {
      const errorMessages = errors.array().map((err: ValidationError) => ({
        param: err.param,
        message: err.msg,
        value: err.value
      }));
      
      return res.status(400).json({
        success: false,
        error: 'Invalid route parameters',
        message: 'Parámetros de ruta inválidos',
        errors: errorMessages
      });
    }
    
    next();
  };
};

/**
 * Middleware para validar archivos subidos
 */
export const validateFileUpload = (options: {
  fieldName: string;
  allowedTypes: string[];
  maxSize?: number; // en bytes
}) => {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!req.files || !req.files[options.fieldName]) {
      return next();
    }
    
    const file = Array.isArray(req.files[options.fieldName]) 
      ? req.files[options.fieldName][0] 
      : req.files[options.fieldName];
    
    // Verificar tipo de archivo
    if (!options.allowedTypes.includes(file.mimetype)) {
      return res.status(400).json({
        success: false,
        error: 'Invalid file type',
        message: `Tipo de archivo no permitido. Tipos permitidos: ${options.allowedTypes.join(', ')}`
      });
    }
    
    // Verificar tamaño del archivo
    if (options.maxSize && file.size > options.maxSize) {
      return res.status(400).json({
        success: false,
        error: 'File too large',
        message: `El archivo es demasiado grande. Tamaño máximo permitido: ${options.maxSize / 1024 / 1024}MB`
      });
    }
    
    next();
  };
};
