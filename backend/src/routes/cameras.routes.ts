import express, { Router } from 'express';
import { CamerasController } from '../controllers/cameras.controller';
import { authenticate } from '../middleware/auth.middleware';
import { rateLimiter } from '../middleware/rateLimiter';
import {
  validateDiscovery,
  validateCamera,
  validatePTZControl,
  validateCameraId,
  validateStreamType,
  checkCameraOwnership,
  checkCameraOnline,
  checkPTZSupport
} from '../middleware/camera-validation.middleware';

// Initialize router and controller
const router = Router();
const camerasController = new CamerasController(
  new (require('../services/onvif.service').ONVIFService)(),
  new (require('@prisma/client').PrismaClient)()
);

// Rate limiting for camera endpoints
const cameraLimiter = rateLimiter.rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 30, // Limit each IP to 30 requests per minute
  message: 'Too many requests, please try again later.'
});

// Asegurarse de que el objeto Prisma esté disponible en la solicitud
declare global {
  namespace Express {
    interface Request {
      prisma: any; // Ajusta el tipo según tu implementación de Prisma
      user: {
        id: string;
        [key: string]: any;
      };
      camera?: any; // Ajusta el tipo según tu modelo de cámara
    }
  }
}

// Apply authentication middleware to all camera routes
router.use(authenticate);

// Apply rate limiting to all camera routes
router.use(cameraLimiter);

// Rutas de cámaras
router.get('/', camerasController.getCameras);
router.get(
  '/:id',
  validateCameraId,
  checkCameraOwnership,
  camerasController.getCameraById
);

router.post(
  '/discover',
  validateDiscovery,
  camerasController.discoverCameras
);

router.post(
  '/',
  validateCamera,
  camerasController.addCamera
);

router.put(
  '/:id',
  validateCameraId,
  checkCameraOwnership,
  ...validateCamera,
  camerasController.updateCamera
);

router.delete(
  '/:id',
  validateCameraId,
  checkCameraOwnership,
  camerasController.deleteCamera
);

router.get(
  '/:id/test-connection',
  validateCameraId,
  checkCameraOwnership,
  camerasController.testConnection
);

router.get(
  '/:id/stream',
  validateCameraId,
  validateStreamType,
  checkCameraOwnership,
  checkCameraOnline,
  camerasController.getCameraStream
);

router.post(
  '/:id/ptz',
  validateCameraId,
  validatePTZControl,
  checkCameraOwnership,
  checkCameraOnline,
  checkPTZSupport,
  camerasController.controlPTZ
);

export default router;
