import { describe, it, expect, jest, beforeEach, afterEach } from '@jest/globals';
import { HeartbeatWorker } from '../heartbeat.worker';
import { PrismaClient } from '@prisma/client';
import { ONVIFService } from '../../services/onvif.service';
import { io } from '../../app';

// Mock de las dependencias
jest.mock('@prisma/client');
jest.mock('../../services/onvif.service');
jest.mock('../../app');

describe('HeartbeatWorker', () => {
  let heartbeatWorker: HeartbeatWorker;
  let mockPrisma: jest.Mocked<PrismaClient>;
  let mockOnvifService: jest.Mocked<ONVIFService>;

  beforeEach(() => {
    // Limpiar todas las instancias y llamadas a constructor y métodos
    jest.clearAllMocks();

    // Configurar mocks
    mockPrisma = new PrismaClient() as jest.Mocked<PrismaClient>;
    mockOnvifService = new ONVIFService() as jest.Mocked<ONVIFService>;

    // Mock de los métodos de Prisma
    mockPrisma.camera = {
      findMany: jest.fn(),
      findUnique: jest.fn(),
      update: jest.fn(),
      updateMany: jest.fn(),
    } as any;

    mockPrisma.failedHeartbeat = {
      create: jest.fn(),
      updateMany: jest.fn(),
    } as any;

    // Mock del método performHeartbeat
    mockOnvifService.performHeartbeat = jest.fn();

    // Crear instancia del worker con los mocks
    heartbeatWorker = new HeartbeatWorker();
    // @ts-ignore
    heartbeatWorker['prisma'] = mockPrisma;
    // @ts-ignore
    heartbeatWorker['onvifService'] = mockOnvifService;
  });

  afterEach(async () => {
    // Limpiar cualquier temporizador pendiente
    jest.clearAllTimers();
    await heartbeatWorker.close();
  });

  describe('checkCameraStatus', () => {
    it('debe actualizar el estado de la cámara a online cuando todo está bien', async () => {
      // Configurar el mock para devolver una cámara
      const mockCamera = {
        id: 'camera-1',
        name: 'Test Camera',
        ipAddress: '192.168.1.100',
        port: 80,
        username: 'admin',
        password: 'password',
        manufacturer: 'Hikvision',
        isOnline: false,
        status: 'offline',
        rtspUrls: [
          { url: 'rtsp://192.168.1.100/stream', isActive: true }
        ],
        _count: {
          failedHeartbeats: 0
        }
      };

      mockPrisma.camera.findUnique.mockResolvedValue(mockCamera);
      mockPrisma.camera.update.mockResolvedValue({
        ...mockCamera,
        isOnline: true,
        status: 'active'
      });

      // Configurar el mock de performHeartbeat
      mockOnvifService.performHeartbeat.mockResolvedValue({
        isOnline: true,
        ping: true,
        onvif: true,
        rtsp: true,
        lastSeen: new Date(),
        uptime: 3600
      });

      // Ejecutar la prueba
      const result = await heartbeatWorker['checkCameraStatus']('camera-1');

      // Verificar resultados
      expect(result).toBe(true);
      expect(mockPrisma.camera.update).toHaveBeenCalledWith({
        where: { id: 'camera-1' },
        data: expect.objectContaining({
          isOnline: true,
          status: 'active'
        }),
        include: expect.anything()
      });
    });

    it('debe manejar correctamente una cámara offline', async () => {
      // Configurar el mock para devolver una cámara
      const mockCamera = {
        id: 'camera-1',
        name: 'Test Camera',
        ipAddress: '192.168.1.100',
        isOnline: true,
        status: 'active',
        rtspUrls: [],
        _count: {
          failedHeartbeats: 0
        }
      };

      mockPrisma.camera.findUnique.mockResolvedValue(mockCamera);
      mockPrisma.camera.update.mockResolvedValue({
        ...mockCamera,
        isOnline: false,
        status: 'offline'
      });

      // Configurar el mock de performHeartbeat para simular fallo
      mockOnvifService.performHeartbeat.mockResolvedValue({
        isOnline: false,
        ping: false,
        onvif: false,
        rtsp: false,
        error: 'Connection timeout'
      });

      // Ejecutar la prueba
      const result = await heartbeatWorker['checkCameraStatus']('camera-1');

      // Verificar resultados
      expect(result).toBe(false);
      expect(mockPrisma.failedHeartbeat.create).toHaveBeenCalledWith({
        data: {
          cameraId: 'camera-1',
          reason: 'No response to ping',
          details: expect.any(String)
        }
      });
    });
  });

  describe('checkAllCameras', () => {
    it('debe verificar todas las cámaras activas', async () => {
      // Configurar el mock para devolver una lista de cámaras
      const mockCameras = [
        { id: 'camera-1', name: 'Camera 1', ipAddress: '192.168.1.100', status: 'active', rtspUrls: [] },
        { id: 'camera-2', name: 'Camera 2', ipAddress: '192.168.1.101', status: 'active', rtspUrls: [] },
      ];

      mockPrisma.camera.findMany.mockResolvedValue(mockCameras);
      
      // Mock de checkCameraStatus para simular éxito
      const originalCheckCameraStatus = heartbeatWorker['checkCameraStatus'].bind(heartbeatWorker);
      heartbeatWorker['checkCameraStatus'] = jest.fn().mockResolvedValue(true);

      // Ejecutar la prueba
      await heartbeatWorker['checkAllCameras']();

      // Verificar resultados
      expect(mockPrisma.camera.findMany).toHaveBeenCalledWith({
        where: {
          status: {
            in: ['active', 'warning', 'offline']
          }
        },
        include: {
          rtspUrls: {
            where: { isActive: true },
            take: 1
          }
        }
      });

      // Verificar que se llamó a checkCameraStatus para cada cámara
      expect(heartbeatWorker['checkCameraStatus']).toHaveBeenCalledTimes(2);
      expect(heartbeatWorker['checkCameraStatus']).toHaveBeenCalledWith('camera-1', false);
      expect(heartbeatWorker['checkCameraStatus']).toHaveBeenCalledWith('camera-2', false);

      // Restaurar el método original
      heartbeatWorker['checkCameraStatus'] = originalCheckCameraStatus;
    });
  });

  describe('notifyStatusChange', () => {
    it('debe emitir un evento de cambio de estado a través de Socket.IO', () => {
      // Configurar el mock de io
      const mockEmit = jest.fn();
      // @ts-ignore
      io.to.mockReturnValue({ emit: mockEmit });

      const mockCamera = {
        id: 'camera-1',
        userId: 'user-1',
        isOnline: true,
        status: 'active',
        lastSeen: new Date(),
        uptime: 3600
      };

      // Ejecutar la prueba
      heartbeatWorker['notifyStatusChange'](mockCamera);

      // Verificar que se emitieron los eventos correctos
      expect(io.to).toHaveBeenCalledWith('camera:camera-1');
      expect(mockEmit).toHaveBeenCalledWith('camera:status', {
        cameraId: 'camera-1',
        isOnline: true,
        status: 'active',
        lastSeen: expect.any(Date),
        uptime: 3600
      });

      // Verificar que también se notificó al usuario
      expect(io.to).toHaveBeenCalledWith('user:user-1');
    });
  });

  describe('close', () => {
    it('debe cerrar correctamente el worker y liberar recursos', async () => {
      // Configurar el worker con un temporizador activo
      // @ts-ignore
      heartbeatWorker['intervalId'] = setTimeout(() => {}, 1000);
      
      // Mock de worker.close()
      // @ts-ignore
      heartbeatWorker['worker'] = { close: jest.fn().mockResolvedValue(undefined) };
      
      // Ejecutar la prueba
      await heartbeatWorker.close();

      // Verificar que se limpiaron los recursos
      expect(clearInterval).toHaveBeenCalled();
      // @ts-ignore
      expect(heartbeatWorker['worker'].close).toHaveBeenCalled();
      expect(mockPrisma.$disconnect).toHaveBeenCalled();
    });
  });
});
