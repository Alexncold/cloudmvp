import { describe, it, expect, jest, beforeEach, afterEach } from '@jest/globals';
import { Request, Response, NextFunction } from 'express';
import { v4 as uuidv4 } from 'uuid';
import { Worker } from 'bullmq';
import { createClient } from 'redis';
import { DiscoveryController } from '../../../src/controllers/discoveryController';
import { ApiError } from '../../../src/utils/errors';

// Mock de los módulos externos
jest.mock('bullmq');
jest.mock('redis');

// Mock de la configuración de Redis
const mockRedisClient = {
  connect: jest.fn().mockResolvedValue(undefined),
  get: jest.fn(),
  set: jest.fn(),
  hSet: jest.fn(),
  hGetAll: jest.fn(),
  multi: jest.fn(() => ({
    set: jest.fn().mockReturnThis(),
    hSet: jest.fn().mockReturnThis(),
    expire: jest.fn().mockReturnThis(),
    exec: jest.fn().mockResolvedValue(undefined),
  })),
  on: jest.fn(),
};

// Mock del worker de BullMQ
const mockWorker = {
  add: jest.fn().mockResolvedValue({ id: 'job-123' }),
  getJob: jest.fn(),
  on: jest.fn(),
};

// Configurar los mocks antes de cada prueba
beforeEach(() => {
  // Limpiar todas las instancias y llamadas a constructores
  jest.clearAllMocks();
  
  // Configurar los mocks de los módulos
  (createClient as jest.Mock).mockReturnValue(mockRedisClient);
  (Worker as jest.Mock).mockImplementation(() => mockWorker);
});

describe('DiscoveryController', () => {
  let discoveryController: DiscoveryController;
  let req: Partial<Request>;
  let res: Partial<Response>;
  let next: jest.Mock<NextFunction>;
  
  // Datos de prueba
  const mockSessionId = uuidv4();
  const mockUserId = 'user-123';
  const mockDiscoveryOptions = {
    networkRanges: ['192.168.1.0/24'],
    scanPorts: [80, 443],
    protocols: ['onvif'],
    timeout: 30000,
    maxConcurrentScans: 5,
  };
  
  // Configuración común antes de cada prueba
  beforeEach(() => {
    // Crear una instancia del controlador
    discoveryController = DiscoveryController.getInstance();
    
    // Configurar objetos de solicitud y respuesta simulados
    req = {
      params: {},
      query: {},
      body: {},
      user: { id: mockUserId, isAdmin: false },
    };
    
    res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
      send: jest.fn(),
    };
    
    next = jest.fn();
  });
  
  // Pruebas para el método startDiscovery
  describe('startDiscovery', () => {
    it('debe iniciar un nuevo descubrimiento con opciones válidas', async () => {
      // Configurar la solicitud
      req.body = mockDiscoveryOptions;
      
      // Configurar el mock de Redis para simular una sesión no existente
      mockRedisClient.get.mockResolvedValue(null);
      
      // Llamar al método del controlador
      await discoveryController.startDiscovery(
        req as Request,
        res as Response,
        next
      );
      
      // Verificar la respuesta
      expect(res.status).toHaveBeenCalledWith(202);
      expect(res.json).toHaveBeenCalledWith(expect.objectContaining({
        success: true,
        message: 'Descubrimiento de cámaras iniciado',
      }));
      
      // Verificar que se creó un nuevo trabajo en el worker
      expect(mockWorker.add).toHaveBeenCalledWith(
        'discovery-job',
        expect.objectContaining({
          options: mockDiscoveryOptions,
          userId: mockUserId,
        }),
        expect.any(Object)
      );
    });
    
    it('debe rechazar rangos de red no permitidos', async () => {
      // Configurar un rango de red no permitido
      req.body = {
        ...mockDiscoveryOptions,
        networkRanges: ['10.0.0.0/8'], // Asumiendo que no está en ALLOWED_NETWORK_RANGES
      };
      
      // Configurar las variables de entorno para la prueba
      process.env.ALLOWED_NETWORK_RANGES = '192.168.0.0/16,172.16.0.0/12';
      
      // Llamar al método del controlador
      await discoveryController.startDiscovery(
        req as Request,
        res as Response,
        next
      );
      
      // Verificar que se llamó a next con un error
      expect(next).toHaveBeenCalledWith(expect.any(ApiError));
      const error = (next.mock.calls[0][0] as ApiError);
      expect(error.statusCode).toBe(403);
      expect(error.message).toContain('no está permitido');
    });
  });
  
  // Pruebas para el método getDiscoveryStatus
  describe('getDiscoveryStatus', () => {
    it('debe devolver el estado de una sesión existente', async () => {
      // Configurar el ID de sesión en los parámetros de la ruta
      req.params = { sessionId: mockSessionId };
      
      // Configurar el mock de Redis para devolver una sesión simulada
      const mockSession = {
        id: mockSessionId,
        userId: mockUserId,
        status: 'running',
        phase: 'scanning',
        progress: 50,
        startTime: new Date().toISOString(),
        options: mockDiscoveryOptions,
        devices: [],
      };
      
      mockRedisClient.get.mockResolvedValue(JSON.stringify(mockSession));
      mockRedisClient.hGetAll.mockResolvedValue({});
      
      // Llamar al método del controlador
      await discoveryController.getDiscoveryStatus(
        req as Request,
        res as Response,
        next
      );
      
      // Verificar la respuesta
      expect(res.json).toHaveBeenCalledWith(expect.objectContaining({
        success: true,
        sessionId: mockSessionId,
        status: 'running',
        progress: 50,
      }));
    });
    
    it('debe devolver un error 404 si la sesión no existe', async () => {
      // Configurar un ID de sesión que no existe
      req.params = { sessionId: 'non-existent-session' };
      mockRedisClient.get.mockResolvedValue(null);
      
      // Llamar al método del controlador
      await discoveryController.getDiscoveryStatus(
        req as Request,
        res as Response,
        next
      );
      
      // Verificar que se llamó a next con un error 404
      expect(next).toHaveBeenCalledWith(expect.any(ApiError));
      const error = (next.mock.calls[0][0] as ApiError);
      expect(error.statusCode).toBe(404);
    });
    
    it('debe denegar el acceso a sesiones de otros usuarios', async () => {
      // Configurar una sesión que pertenece a otro usuario
      const otherUserId = 'other-user-456';
      const mockSession = {
        id: mockSessionId,
        userId: otherUserId, // ID de usuario diferente
        status: 'running',
        // ...otros campos
      };
      
      req.params = { sessionId: mockSessionId };
      mockRedisClient.get.mockResolvedValue(JSON.stringify(mockSession));
      
      // Llamar al método del controlador
      await discoveryController.getDiscoveryStatus(
        req as Request,
        res as Response,
        next
      );
      
      // Verificar que se denegó el acceso
      expect(next).toHaveBeenCalledWith(expect.any(ApiError));
      const error = (next.mock.calls[0][0] as ApiError);
      expect(error.statusCode).toBe(403);
    });
  });
  
  // Pruebas para el método cancelDiscovery
  describe('cancelDiscovery', () => {
    it('debe cancelar un descubrimiento en curso', async () => {
      // Configurar el ID de sesión en los parámetros de la ruta
      req.params = { sessionId: mockSessionId };
      
      // Configurar el mock de Redis para devolver una sesión en ejecución
      const mockSession = {
        id: mockSessionId,
        userId: mockUserId,
        status: 'running',
        phase: 'scanning',
        progress: 30,
        startTime: new Date().toISOString(),
        options: mockDiscoveryOptions,
        devices: [],
      };
      
      mockRedisClient.get.mockResolvedValue(JSON.stringify(mockSession));
      mockWorker.getJob.mockResolvedValue({
        id: mockSessionId,
        moveToFailed: jest.fn().mockResolvedValue(undefined),
      });
      
      // Llamar al método del controlador
      await discoveryController.cancelDiscovery(
        req as Request,
        res as Response,
        next
      );
      
      // Verificar la respuesta
      expect(res.json).toHaveBeenCalledWith(expect.objectContaining({
        success: true,
        message: 'Descubrimiento cancelado correctamente',
        sessionId: mockSessionId,
        status: 'cancelled',
      }));
      
      // Verificar que se actualizó el estado de la sesión
      expect(mockRedisClient.set).toHaveBeenCalledWith(
        expect.stringContaining(mockSessionId),
        expect.any(String),
        { EX: expect.any(Number) }
      );
    });
    
    it('debe devolver un error si el descubrimiento no está en curso', async () => {
      // Configurar una sesión que ya está completada
      const mockSession = {
        id: mockSessionId,
        userId: mockUserId,
        status: 'completed', // Ya completada
        // ...otros campos
      };
      
      req.params = { sessionId: mockSessionId };
      mockRedisClient.get.mockResolvedValue(JSON.stringify(mockSession));
      
      // Llamar al método del controlador
      await discoveryController.cancelDiscovery(
        req as Request,
        res as Response,
        next
      );
      
      // Verificar que se devolvió un error
      expect(next).toHaveBeenCalledWith(expect.any(ApiError));
      const error = (next.mock.calls[0][0] as ApiError);
      expect(error.statusCode).toBe(400);
      expect(error.message).toContain('no está en curso');
    });
  });
  
  // Pruebas para el método getDiscoveredDevices
  describe('getDiscoveredDevices', () => {
    it('debe devolver los dispositivos descubiertos con paginación', async () => {
      // Crear dispositivos de prueba
      const mockDevices = Array(10).fill(null).map((_, i) => ({
        id: `device-${i}`,
        ip: `192.168.1.${i + 1}`,
        port: 80,
        protocol: 'http',
        status: 'online',
        // ...otros campos del dispositivo
      }));
      
      // Configurar la solicitud con parámetros de paginación
      req.params = { sessionId: mockSessionId };
      req.query = { page: '2', limit: '3' };
      
      // Configurar el mock de Redis para devolver la sesión y los dispositivos
      const mockSession = {
        id: mockSessionId,
        userId: mockUserId,
        status: 'completed',
        devices: mockDevices,
        // ...otros campos
      };
      
      mockRedisClient.get.mockResolvedValue(JSON.stringify(mockSession));
      
      // Llamar al método del controlador
      await discoveryController.getDiscoveredDevices(
        req as Request,
        res as Response,
        next
      );
      
      // Verificar la respuesta
      expect(res.json).toHaveBeenCalledWith(expect.objectContaining({
        success: true,
        sessionId: mockSessionId,
        page: 2,
        limit: 3,
        total: 10,
        totalPages: 4, // 10 dispositivos / 3 por página = 4 páginas
        devices: expect.arrayContaining([
          expect.objectContaining({ id: 'device-3' }),
          expect.objectContaining({ id: 'device-4' }),
          expect.objectContaining({ id: 'device-5' }),
        ]),
      }));
    });
  });
  
  // Pruebas para el método getDiscoveryHistory
  describe('getDiscoveryHistory', () => {
    it('debe devolver el historial de descubrimientos del usuario', async () => {
      // Configurar la solicitud con parámetros de paginación
      req.query = { page: '1', limit: '5' };
      
      // Configurar el usuario como administrador para probar el filtrado
      (req.user as any).isAdmin = true;
      
      // Configurar el mock de Redis para simular múltiples sesiones
      const mockSessions = Array(8).fill(null).map((_, i) => ({
        id: `session-${i}`,
        userId: i % 2 === 0 ? mockUserId : `other-user-${i}`,
        status: i % 2 === 0 ? 'completed' : 'failed',
        startTime: new Date(Date.now() - i * 3600000).toISOString(),
        // ...otros campos
      }));
      
      // Simular que el controlador tiene estas sesiones en memoria
      // En una implementación real, esto se haría mediante el mock de Redis
      jest.spyOn(discoveryController as any, 'getSession')
        .mockImplementation(async (sessionId: string) => {
          return mockSessions.find(s => s.id === sessionId) || null;
        });
      
      // Llamar al método del controlador
      await discoveryController.getDiscoveryHistory(
        req as Request,
        res as Response,
        next
      );
      
      // Verificar la respuesta
      expect(res.json).toHaveBeenCalledWith(expect.objectContaining({
        success: true,
        page: 1,
        limit: 5,
        total: 8, // Todas las sesiones porque es admin
        totalPages: 2, // 8 sesiones / 5 por página = 2 páginas
        sessions: expect.arrayContaining([
          expect.objectContaining({
            id: expect.any(String),
            status: expect.any(String),
          }),
        ]),
      }));
    });
  });
  
  // Pruebas para el método exportDevices
  describe('exportDevices', () => {
    it('debe exportar dispositivos en formato JSON', async () => {
      // Configurar la solicitud para exportar en formato JSON
      req.params = { sessionId: mockSessionId };
      req.query = { format: 'json' };
      
      // Configurar el mock de Redis para devolver una sesión con dispositivos
      const mockDevices = [
        { id: 'device-1', ip: '192.168.1.10', port: 80, protocol: 'http' },
        { id: 'device-2', ip: '192.168.1.11', port: 443, protocol: 'https' },
      ];
      
      const mockSession = {
        id: mockSessionId,
        userId: mockUserId,
        status: 'completed',
        devices: mockDevices,
        // ...otros campos
      };
      
      mockRedisClient.get.mockResolvedValue(JSON.stringify(mockSession));
      
      // Configurar el objeto de respuesta para probar la descarga
      const mockResponse = {
        setHeader: jest.fn(),
        send: jest.fn(),
      };
      
      // Llamar al método del controlador
      await discoveryController.exportDevices(
        req as Request,
        mockResponse as unknown as Response,
        next
      );
      
      // Verificar que se configuraron los encabezados correctos
      expect(mockResponse.setHeader).toHaveBeenCalledWith(
        'Content-Type',
        'application/json'
      );
      expect(mockResponse.setHeader).toHaveBeenCalledWith(
        'Content-Disposition',
        expect.stringContaining('devices_')
      );
      
      // Verificar que se enviaron los datos JSON
      expect(mockResponse.send).toHaveBeenCalledWith(
        JSON.stringify(mockDevices, null, 2)
      );
    });
    
    it('debe exportar dispositivos en formato CSV', async () => {
      // Configurar la solicitud para exportar en formato CSV
      req.params = { sessionId: mockSessionId };
      req.query = { format: 'csv' };
      
      // Configurar el mock de Redis para devolver una sesión con dispositivos
      const mockDevices = [
        { id: 'device-1', ip: '192.168.1.10', port: 80, protocol: 'http' },
      ];
      
      const mockSession = {
        id: mockSessionId,
        userId: mockUserId,
        status: 'completed',
        devices: mockDevices,
      };
      
      mockRedisClient.get.mockResolvedValue(JSON.stringify(mockSession));
      
      // Configurar el objeto de respuesta para probar la descarga
      const mockResponse = {
        setHeader: jest.fn(),
        send: jest.fn(),
      };
      
      // Llamar al método del controlador
      await discoveryController.exportDevices(
        req as Request,
        mockResponse as unknown as Response,
        next
      );
      
      // Verificar que se configuraron los encabezados correctos para CSV
      expect(mockResponse.setHeader).toHaveBeenCalledWith(
        'Content-Type',
        'text/csv'
      );
      
      // Verificar que se enviaron los datos CSV
      const csvData = (mockResponse.send.mock.calls[0][0] as string).split('\n');
      expect(csvData[0]).toContain('id,ip,port,protocol');
      expect(csvData[1]).toContain('device-1,192.168.1.10,80,http');
    });
  });
  
  // Pruebas para el manejo de WebSockets
  describe('handleWebSocketConnection', () => {
    it('debe permitir la conexión WebSocket con un ID de sesión válido', () => {
      // Configurar un socket simulado
      const mockSocket = {
        handshake: {
          query: { sessionId: mockSessionId },
        },
        request: {
          user: { id: mockUserId },
        },
        join: jest.fn(),
        emit: jest.fn(),
        disconnect: jest.fn(),
      };
      
      // Configurar el mock de Redis para devolver una sesión válida
      const mockSession = {
        id: mockSessionId,
        userId: mockUserId,
        status: 'running',
        // ...otros campos
      };
      
      mockRedisClient.get.mockResolvedValue(JSON.stringify(mockSession));
      
      // Llamar al método de manejo de WebSocket
      discoveryController.handleWebSocketConnection(mockSocket as any);
      
      // Verificar que el socket se unió a la sala correcta
      expect(mockSocket.join).toHaveBeenCalledWith(`discovery:${mockSessionId}`);
      
      // La verificación de los eventos emitidos se haría con un enfoque asíncrono en una prueba real
      // Aquí solo verificamos que no se haya llamado a disconnect
      expect(mockSocket.disconnect).not.toHaveBeenCalled();
    });
    
    it('debe rechazar la conexión WebSocket sin ID de sesión', () => {
      // Configurar un socket sin ID de sesión
      const mockSocket = {
        handshake: {
          query: {},
        },
        disconnect: jest.fn(),
      };
      
      // Llamar al método de manejo de WebSocket
      discoveryController.handleWebSocketConnection(mockSocket as any);
      
      // Verificar que se desconectó el socket
      expect(mockSocket.disconnect).toHaveBeenCalledWith(true);
    });
  });
});

describe('Validación de opciones de descubrimiento', () => {
  let discoveryController: DiscoveryController;
  
  beforeEach(() => {
    // Crear una instancia del controlador para cada prueba
    discoveryController = DiscoveryController.getInstance();
    
    // Configurar variables de entorno para las pruebas
    process.env.ALLOWED_NETWORK_RANGES = '192.168.0.0/16,10.0.0.0/8';
    process.env.DISCOVERY_MAX_TIMEOUT = '300000';
    process.env.MAX_CONCURRENT_SCANS = '20';
  });
  
  it('debe aceptar rangos de red permitidos', () => {
    const options = {
      networkRanges: ['192.168.1.0/24', '10.0.1.0/24'],
      // ...otras opciones
    };
    
    // Usar el método de validación directamente
    const validatedOptions = (discoveryController as any).validateDiscoveryOptions(options);
    
    // Verificar que los rangos de red se validaron correctamente
    expect(validatedOptions.networkRanges).toEqual(options.networkRanges);
  });
  
  it('debe filtrar rangos de red no permitidos', () => {
    const options = {
      networkRanges: ['192.168.1.0/24', '172.16.0.0/16'], // 172.16.0.0/16 no está permitido
      // ...otras opciones
    };
    
    // Usar el método de validación directamente
    const validatedOptions = (discoveryController as any).validateDiscoveryOptions(options);
    
    // Verificar que se filtró el rango no permitido
    expect(validatedOptions.networkRanges).toEqual(['192.168.1.0/24']);
  });
  
  it('debe limitar el tiempo de espera máximo', () => {
    const options = {
      timeout: 600000, // 10 minutos, más que el máximo permitido
      // ...otras opciones
    };
    
    // Usar el método de validación directamente
    const validatedOptions = (discoveryController as any).validateDiscoveryOptions(options);
    
    // Verificar que se limitó el tiempo de espera
    expect(validatedOptions.timeout).toBe(300000); // 5 minutos (300000 ms)
  });
  
  it('debe limitar el número de escaneos concurrentes', () => {
    const options = {
      maxConcurrentScans: 50, // Más que el máximo permitido
      // ...otras opciones
    };
    
    // Usar el método de validación directamente
    const validatedOptions = (discoveryController as any).validateDiscoveryOptions(options);
    
    // Verificar que se limitó el número de escaneos concurrentes
    expect(validatedOptions.maxConcurrentScans).toBe(20);
  });
  
  it('debe filtrar protocolos no soportados', () => {
    const options = {
      protocols: ['onvif', 'rtsp', 'invalid-protocol'],
      // ...otras opciones
    };
    
    // Usar el método de validación directamente
    const validatedOptions = (discoveryController as any).validateDiscoveryOptions(options);
    
    // Verificar que se filtró el protocolo no soportado
    expect(validatedOptions.protocols).toEqual(['onvif', 'rtsp']);
  });
  
  it('debe lanzar un error si no hay rangos de red válidos', () => {
    const options = {
      networkRanges: ['invalid-range', '172.16.0.0/16'], // Ninguno permitido
      // ...otras opciones
    };
    
    // Verificar que se lanza una excepción
    expect(() => {
      (discoveryController as any).validateDiscoveryOptions(options);
    }).toThrow(ApiError);
  });
});
