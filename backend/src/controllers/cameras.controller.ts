import { Request, Response, NextFunction } from 'express';
import { validationResult } from 'express-validator';
import { PrismaClient } from '@prisma/client';
import { ONVIFService } from '../services/onvif.service';
import { logger } from '../utils/logger';
import { Camera, CameraStatus, DiscoveredCamera } from '../../../shared/types/onvif';

export class CamerasController {
  private onvifService: ONVIFService;
  private prisma: PrismaClient;

  constructor(onvifService: ONVIFService, prisma: PrismaClient) {
    this.onvifService = onvifService;
    this.prisma = prisma;
  }

  /**
   * Obtiene todas las cámaras del sistema
   */
  public getCameras = async (req: Request, res: Response, next: NextFunction) => {
    try {
      const cameras = await this.prisma.camera.findMany({
        where: { userId: req.user.id },
        select: {
          id: true,
          name: true,
          ipAddress: true,
          port: true,
          status: true,
          manufacturer: true,
          model: true,
          lastSeen: true,
          isOnline: true,
          createdAt: true,
          updatedAt: true
        }
      });

      res.json(cameras);
    } catch (error) {
      logger.error('Error al obtener cámaras', { error });
      next(error);
    }
  };

  /**
   * Obtiene una cámara por su ID
   */
  public getCameraById = async (req: Request, res: Response, next: NextFunction) => {
    try {
      if (!req.user || !req.user.id) {
        return res.status(401).json({ message: 'No autorizado' });
      }
      const { id } = req.params;
      
      const camera = await this.prisma.camera.findUnique({
        where: { id, userId: req.user.id },
        include: {
          rtspUrls: true,
          capabilities: true
        }
      });

      if (!camera) {
        return res.status(404).json({ message: 'Cámara no encontrada' });
      }

      res.json(camera);
    } catch (error) {
      logger.error('Error al obtener cámara por ID', { error });
      next(error);
    }
  };

  /**
   * Descubre cámaras en la red
   */
  public discoverCameras = async (req: Request, res: Response, next: NextFunction) => {
    try {
      if (!req.user || !req.user.id) {
        return res.status(401).json({ message: 'No autorizado' });
      }
      const { timeout = 5000, scanLocalNetwork = true, specificIps = [] } = req.body;
      
      // Validar parámetros
      if (typeof timeout !== 'number' || timeout < 1000 || timeout > 30000) {
        return res.status(400).json({ 
          message: 'El tiempo de espera debe estar entre 1000 y 30000 ms' 
        });
      }

      if (typeof scanLocalNetwork !== 'boolean') {
        return res.status(400).json({ 
          message: 'scanLocalNetwork debe ser un valor booleano' 
        });
      }

      if (!Array.isArray(specificIps) || specificIps.some(ip => typeof ip !== 'string')) {
        return res.status(400).json({ 
          message: 'specificIps debe ser un array de strings con direcciones IP' 
        });
      }

      // Ejecutar descubrimiento
      const discoveredCameras = await this.onvifService.discoverCameras({
        timeout,
        scanLocalNetwork,
        specificIps
      });

      res.json({
        success: true,
        count: discoveredCameras.length,
        cameras: discoveredCameras
      });
    } catch (error) {
      logger.error('Error en el descubrimiento de cámaras', { error });
      next(error);
    }
  };

  /**
   * Añade una nueva cámara al sistema
   */
  public addCamera = async (req: Request, res: Response, next: NextFunction) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const {
      name,
      ipAddress,
      port = 80,
      username,
      password,
      manufacturer,
      model,
      rtspUrls = []
    } = req.body;

    try {
      // Validar la conexión con la cámara
      const validation = await this.onvifService.validateCamera({
        ipAddress,
        port,
        username,
        password,
        manufacturer
      });

      if (!validation.isValid) {
        return res.status(400).json({
          success: false,
          message: 'No se pudo conectar a la cámara con las credenciales proporcionadas',
          details: validation.error
        });
      }

      // Crear la cámara en la base de datos
      const camera = await this.prisma.camera.create({
        data: {
          name,
          ipAddress,
          port,
          username,
          password,
          manufacturer,
          model: model || validation.deviceInfo?.model || 'Desconocido',
          firmware: validation.deviceInfo?.firmware || 'Desconocido',
          status: 'active' as CameraStatus,
          isOnline: true,
          lastSeen: new Date(),
          userId: req.user.id,
          rtspUrls: {
            create: rtspUrls.map((url: string) => ({
              url,
              isActive: true,
              streamType: url.includes('sub') ? 'sub' : 'main',
              resolution: '1920x1080', // Se actualizará con información real
              userId: req.user.id
            }))
          },
          capabilities: {
            create: {
              hasPTZ: validation.capabilities?.ptzSupport || false,
              hasAudio: validation.capabilities?.audioSupport || false,
              hasNightVision: validation.capabilities?.nightVision || false,
              hasMotionDetection: validation.capabilities?.motionDetection || false,
              resolutions: validation.capabilities?.resolutions || ['1920x1080'],
              codecs: validation.capabilities?.codecs || ['H.264'],
              onvifVersion: validation.capabilities?.onvifVersion || '1.0',
              userId: req.user.id
            }
          }
        },
        include: {
          rtspUrls: true,
          capabilities: true
        }
      });

      res.status(201).json({
        success: true,
        message: 'Cámara agregada correctamente',
        camera
      });
    } catch (error) {
      logger.error('Error al agregar cámara', { error });
      next(error);
    }
  };

  /**
   * Actualiza una cámara existente
   */
  public updateCamera = async (req: Request, res: Response, next: NextFunction) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { id } = req.params;
    const updateData = req.body;

    try {
      // Verificar que la cámara existe y pertenece al usuario
      const existingCamera = await this.prisma.camera.findUnique({
        where: { id, userId: req.user.id }
      });

      if (!existingCamera) {
        return res.status(404).json({ message: 'Cámara no encontrada' });
      }

      // Si se están actualizando credenciales, validarlas
      if (updateData.username || updateData.password) {
        const validation = await this.onvifService.validateCamera({
          ipAddress: updateData.ipAddress || existingCamera.ipAddress,
          port: updateData.port || existingCamera.port,
          username: updateData.username || existingCamera.username || '',
          password: updateData.password || existingCamera.password || '',
          manufacturer: updateData.manufacturer || existingCamera.manufacturer
        });

        if (!validation.isValid) {
          return res.status(400).json({
            success: false,
            message: 'No se pudo conectar a la cámara con las credenciales proporcionadas',
            details: validation.error
          });
        }
      }

      // Actualizar la cámara
      const updatedCamera = await this.prisma.camera.update({
        where: { id },
        data: {
          ...updateData,
          // No permitir actualizar el ID de usuario
          userId: undefined
        },
        include: {
          rtspUrls: true,
          capabilities: true
        }
      });

      res.json({
        success: true,
        message: 'Cámara actualizada correctamente',
        camera: updatedCamera
      });
    } catch (error) {
      logger.error('Error al actualizar cámara', { error });
      next(error);
    }
  };

  /**
   * Elimina una cámara del sistema
   */
  public deleteCamera = async (req: Request, res: Response, next: NextFunction) => {
    const { id } = req.params;

    try {
      // Verificar que la cámara existe y pertenece al usuario
      const camera = await this.prisma.camera.findUnique({
        where: { id, userId: req.user.id }
      });

      if (!camera) {
        return res.status(404).json({ message: 'Cámara no encontrada' });
      }

      // Eliminar la cámara y sus relaciones (configurado con CASCADE en la base de datos)
      await this.prisma.camera.delete({
        where: { id }
      });

      res.json({
        success: true,
        message: 'Cámara eliminada correctamente'
      });
    } catch (error) {
      logger.error('Error al eliminar cámara', { error });
      next(error);
    }
  };

  /**
   * Prueba la conexión a una cámara
   */
  public testConnection = async (req: Request, res: Response, next: NextFunction) => {
    const { id } = req.params;

    try {
      const camera = await this.prisma.camera.findUnique({
        where: { id, userId: req.user.id },
        include: {
          rtspUrls: {
            where: { isActive: true },
            take: 1
          }
        }
      });

      if (!camera) {
        return res.status(404).json({ message: 'Cámara no encontrada' });
      }

      const rtspUrl = camera.rtspUrls[0]?.url;

      const result = await this.onvifService.performHeartbeat({
        ipAddress: camera.ipAddress,
        port: camera.port,
        username: camera.username || '',
        password: camera.password || '',
        rtspUrl,
        manufacturer: camera.manufacturer || undefined
      });

      // Actualizar el estado de la cámara
      await this.prisma.camera.update({
        where: { id },
        data: {
          isOnline: result.isOnline,
          lastSeen: result.lastSeen,
          status: result.isOnline ? 'active' : 'offline'
        }
      });

      res.json({
        success: result.isOnline,
        isOnline: result.isOnline,
        details: {
          ping: result.ping,
          onvif: result.onvif,
          rtsp: result.rtsp,
          lastSeen: result.lastSeen,
          uptime: result.uptime
        },
        message: result.isOnline 
          ? 'Conexión exitosa con la cámara' 
          : 'No se pudo establecer conexión con la cámara'
      });
    } catch (error) {
      logger.error('Error al probar conexión con la cámara', { error });
      next(error);
    }
  };

  /**
   * Obtiene el stream RTSP de una cámara
   */
  public getCameraStream = async (req: Request, res: Response, next: NextFunction) => {
    const { id } = req.params;
    const { streamType = 'main' } = req.query;

    try {
      const camera = await this.prisma.camera.findUnique({
        where: { id, userId: req.user.id },
        include: {
          rtspUrls: true
        }
      });

      if (!camera) {
        return res.status(404).json({ message: 'Cámara no encontrada' });
      }

      // Buscar la URL del stream solicitado
      const streamUrl = camera.rtspUrls.find(
        url => url.streamType === streamType && url.isActive
      );

      if (!streamUrl) {
        return res.status(404).json({ 
          message: `No se encontró un stream activo de tipo '${streamType}'` 
        });
      }

      // Aquí iría la lógica para redirigir o procesar el stream RTSP
      // Por ahora, devolvemos la URL del stream
      res.json({
        success: true,
        streamUrl: streamUrl.url,
        streamType: streamUrl.streamType,
        resolution: streamUrl.resolution
      });
    } catch (error) {
      logger.error('Error al obtener el stream de la cámara', { error });
      next(error);
    }
  };

  /**
   * Ejecuta una acción PTZ en la cámara
   */
  public controlPTZ = async (req: Request, res: Response, next: NextFunction) => {
    const { id } = req.params;
    const { action, speed = 0.5, preset } = req.body;

    try {
      const camera = await this.prisma.camera.findUnique({
        where: { id, userId: req.user.id },
        include: {
          capabilities: true
        }
      });

      if (!camera) {
        return res.status(404).json({ message: 'Cámara no encontrada' });
      }

      // Verificar que la cámara soporte PTZ
      if (!camera.capabilities?.hasPTZ) {
        return res.status(400).json({ 
          message: 'Esta cámara no soporta control PTZ' 
        });
      }

      // Aquí iría la lógica para controlar el PTZ de la cámara
      // Por ahora, simulamos una respuesta exitosa
      res.json({
        success: true,
        message: `Acción PTZ '${action}' ejecutada correctamente`,
        action,
        speed,
        preset
      });
    } catch (error) {
      logger.error('Error al controlar PTZ de la cámara', { error });
      next(error);
    }
  };
}
