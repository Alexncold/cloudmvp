import { body, param, query, ValidationChain } from 'express-validator';
import { Request, Response, NextFunction } from 'express';
import { validateRequest } from './validation';

/**
 * Validación para el descubrimiento de cámaras
 */
export const validateDiscovery = [
  body('timeout')
    .optional()
    .isInt({ min: 1000, max: 30000 })
    .withMessage('Timeout must be between 1000 and 30000 ms'),
  body('scanLocalNetwork')
    .optional()
    .isBoolean()
    .withMessage('scanLocalNetwork must be a boolean'),
  body('specificIps')
    .optional()
    .isArray()
    .withMessage('specificIps must be an array'),
  body('specificIps.*')
    .isIP()
    .withMessage('Each IP in specificIps must be a valid IP address'),
  validateRequest
];

/**
 * Validación para la creación/actualización de cámaras
 */
export const validateCamera = [
  body('name')
    .trim()
    .notEmpty()
    .withMessage('Name is required')
    .isLength({ max: 100 })
    .withMessage('Name cannot exceed 100 characters'),
  body('ipAddress')
    .isIP()
    .withMessage('A valid IP address is required'),
  body('port')
    .optional()
    .isPort()
    .withMessage('A valid port number is required'),
  body('username')
    .optional()
    .isLength({ max: 100 })
    .withMessage('Username cannot exceed 100 characters'),
  body('password')
    .optional()
    .isLength({ max: 100 })
    .withMessage('Password cannot exceed 100 characters'),
  body('manufacturer')
    .optional()
    .isLength({ max: 50 })
    .withMessage('Manufacturer cannot exceed 50 characters'),
  body('model')
    .optional()
    .isLength({ max: 50 })
    .withMessage('Model cannot exceed 50 characters'),
  body('rtspUrls')
    .optional()
    .isArray()
    .withMessage('RTSP URLs must be an array'),
  body('rtspUrls.*')
    .isURL({
      protocols: ['rtsp'],
      require_protocol: true,
      require_valid_protocol: true
    })
    .withMessage('Each RTSP URL must be a valid RTSP URL'),
  validateRequest
];

/**
 * Validación para el control PTZ
 */
export const validatePTZControl = [
  body('action')
    .isIn(['up', 'down', 'left', 'right', 'zoomIn', 'zoomOut', 'stop', 'preset', 'home'])
    .withMessage('Invalid PTZ action'),
  body('speed')
    .optional()
    .isFloat({ min: 0, max: 1 })
    .withMessage('Speed must be a number between 0 and 1'),
  body('preset')
    .optional()
    .isInt({ min: 1 })
    .withMessage('Preset must be a positive integer'),
  validateRequest
];

/**
 * Validación para parámetros de ruta de ID de cámara
 */
export const validateCameraId = [
  param('id')
    .isUUID()
    .withMessage('Invalid camera ID'),
  validateRequest
];

/**
 * Validación para parámetros de consulta de tipo de stream
 */
export const validateStreamType = [
  query('streamType')
    .optional()
    .isIn(['main', 'sub', 'mobile'])
    .withMessage('Invalid stream type'),
  validateRequest
];

/**
 * Middleware para verificar que el usuario es propietario de la cámara
 */
export const checkCameraOwnership = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const camera = await req.prisma.camera.findUnique({
      where: { id: req.params.id }
    });

    if (!camera) {
      return res.status(404).json({ message: 'Cámara no encontrada' });
    }

    if (camera.userId !== req.user.id) {
      return res.status(403).json({ message: 'No tienes permiso para acceder a esta cámara' });
    }

    // Adjuntar la cámara al objeto de solicitud para su uso posterior
    req.camera = camera;
    next();
  } catch (error) {
    next(error);
  }
};

/**
 * Middleware para verificar que la cámara está en línea
 */
export const checkCameraOnline = async (req: Request, res: Response, next: NextFunction) => {
  try {
    if (!req.camera) {
      await checkCameraOwnership(req, res, () => {});
    }

    if (!req.camera.isOnline) {
      return res.status(423).json({ 
        message: 'La cámara no está disponible en este momento',
        details: {
          isOnline: false,
          lastSeen: req.camera.lastSeen,
          status: req.camera.status
        }
      });
    }

    next();
  } catch (error) {
    next(error);
  }
};

/**
 * Middleware para verificar que la cámara soporta PTZ
 */
export const checkPTZSupport = async (req: Request, res: Response, next: NextFunction) => {
  try {
    if (!req.camera) {
      await checkCameraOwnership(req, res, () => {});
    }

    const capabilities = await req.prisma.cameraCapabilities.findUnique({
      where: { cameraId: req.camera.id }
    });

    if (!capabilities?.hasPTZ) {
      return res.status(400).json({ 
        message: 'Esta cámara no soporta control PTZ',
        details: {
          hasPTZ: false
        }
      });
    }

    next();
  } catch (error) {
    next(error);
  }
};

export default {
  validateDiscovery,
  validateCamera,
  validatePTZControl,
  validateCameraId,
  validateStreamType,
  checkCameraOwnership,
  checkCameraOnline,
  checkPTZSupport
};
