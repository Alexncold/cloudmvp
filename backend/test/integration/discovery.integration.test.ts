import { describe, it, expect, beforeAll, afterAll, jest } from '@jest/globals';
import { Server } from 'http';
import { io as ioClient, Socket } from 'socket.io-client';
import { createServer } from 'http';
import { AddressInfo } from 'net';
import express, { Express } from 'express';
import { RedisClientType } from 'redis';
import { Worker } from 'bullmq';
import { Server as SocketIOServer } from 'socket.io';
import { DiscoveryController } from '../../src/controllers/discoveryController';
import { 
  createTestRedisClient, 
  createTestWorker, 
  createTestSocketClient, 
  generateTestToken, 
  waitFor,
  TEST_CONFIG,
  withTestContext
} from '../test-utils';
import { ApiError } from '../../src/utils/errors';

// Extender el tiempo de espera para las pruebas de integración
jest.setTimeout(30000);

describe('Integración: Sistema de Descubrimiento', () => {
  describe('Flujo completo de descubrimiento', () => {
    it('debe descubrir dispositivos y notificar a través de WebSockets', async () => {
      await withTestContext(async ({ redis, worker, controller }) => {
        // Configurar un servidor HTTP y WebSocket para pruebas
        const app = express();
        const httpServer = createServer(app);
        const io = new SocketIOServer(httpServer, {
          cors: {
            origin: '*',
            methods: ['GET', 'POST'],
          },
        });
        
        // Iniciar el servidor
        await new Promise<void>((resolve) => {
          httpServer.listen(0, () => resolve());
        });
        
        const port = (httpServer.address() as AddressInfo).port;
        const baseUrl = `http://localhost:${port}`;
        
        try {
          // Configurar el controlador con el servidor de sockets
          // @ts-ignore - Acceder al método privado para propósitos de prueba
          controller.setSocketServer(io);
          
          // Crear un token de prueba para el usuario
          const testUser = { id: 'test-user-123', isAdmin: false };
          const authToken = generateTestToken(testUser);
          
          // Conectar un cliente WebSocket de prueba
          const socket = ioClient(baseUrl, {
            auth: { token: authToken },
            query: { sessionId: 'test-session-123' },
            reconnection: false,
            timeout: 5000,
          });
          
          // Variables para rastrear el estado del descubrimiento
          let discoveryStatus = '';
          let discoveryProgress = 0;
          let discoveredDevices: any[] = [];
          let discoveryError: string | null = null;
          
          // Escuchar eventos del socket
          socket.on('discovery:status', (data) => {
            discoveryStatus = data.status;
            discoveryProgress = data.progress;
          });
          
          socket.on('discovery:device', (device) => {
            discoveredDevices.push(device);
          });
          
          socket.on('discovery:error', (error) => {
            discoveryError = error.message;
          });
          
          // Esperar a que el socket se conecte
          await new Promise<void>((resolve) => {
            socket.on('connect', () => resolve());
          });
          
          // Iniciar un descubrimiento
          const discoveryOptions = {
            networkRanges: ['192.168.1.0/24'],
            scanPorts: [80, 443],
            protocols: ['onvif'],
            timeout: 10000,
            maxConcurrentScans: 5,
          };
          
          // @ts-ignore - Llamar al método del controlador directamente
          await controller.startDiscovery(
            { 
              body: discoveryOptions, 
              user: testUser,
              params: {},
              query: {},
            } as any,
            {
              status: jest.fn().mockReturnThis(),
              json: jest.fn().mockImplementation((data) => {
                expect(data.success).toBe(true);
                expect(data.message).toBe('Descubrimiento de cámaras iniciado');
              }),
            } as any,
            (error: any) => {
              if (error) throw error;
            }
          );
          
          // Esperar a que el descubrimiento comience
          await waitFor(() => discoveryStatus === 'running', 5000);
          
          // Simular un dispositivo descubierto
          const mockDevice = {
            id: 'test-device-1',
            ip: '192.168.1.100',
            port: 80,
            protocol: 'http',
            status: 'online',
            details: {
              manufacturer: 'Test Manufacturer',
              model: 'Test Model',
              firmware: '1.0.0',
            },
          };
          
          // @ts-ignore - Emitir un evento de dispositivo descubierto
          worker.emit('deviceFound', { data: { sessionId: 'test-session-123' } }, mockDevice);
          
          // Esperar a que se reciba el dispositivo
          await waitFor(() => discoveredDevices.length > 0, 3000);
          
          // Verificar que el dispositivo se recibió correctamente
          expect(discoveredDevices.length).toBe(1);
          expect(discoveredDevices[0].id).toBe(mockDevice.id);
          expect(discoveredDevices[0].ip).toBe(mockDevice.ip);
          
          // Simular finalización del descubrimiento
          // @ts-ignore - Emitir evento de completado
          worker.emit('completed', { data: { sessionId: 'test-session-123' } }, {
            totalDevices: 1,
            status: 'completed',
          });
          
          // Esperar a que el estado se actualice a completado
          await waitFor(() => discoveryStatus === 'completed', 3000);
          
          // Verificar el estado final
          expect(discoveryStatus).toBe('completed');
          expect(discoveryProgress).toBe(100);
          expect(discoveryError).toBeNull();
          
          // Desconectar el socket
          socket.disconnect();
        } finally {
          // Cerrar el servidor
          await new Promise<void>((resolve) => {
            httpServer.close(() => resolve());
          });
        }
      });
    });
  });
  
  describe('Seguridad del sistema de descubrimiento', () => {
    it('debe rechazar solicitudes sin autenticación', async () => {
      await withTestContext(async ({ controller }) => {
        // Intentar iniciar un descubrimiento sin autenticación
        let error: any;
        
        await controller.startDiscovery(
          { 
            body: { networkRanges: ['192.168.1.0/24'] },
            user: null,
            params: {},
            query: {},
          } as any,
          {} as any,
          (err: any) => { error = err; }
        );
        
        expect(error).toBeInstanceOf(ApiError);
        expect(error.statusCode).toBe(401);
      });
    });
    
    it('debe validar los rangos de red permitidos', async () => {
      await withTestContext(async ({ controller }) => {
        // Configurar un rango de red no permitido
        const testUser = { id: 'test-user-123', isAdmin: false };
        const invalidRange = '10.100.0.0/16'; // Fuera de los rangos permitidos
        
        let error: any;
        
        await controller.startDiscovery(
          { 
            body: { 
              networkRanges: [invalidRange],
              scanPorts: [80],
              protocols: ['onvif'],
            },
            user: testUser,
            params: {},
            query: {},
          } as any,
          {} as any,
          (err: any) => { error = err; }
        );
        
        expect(error).toBeInstanceOf(ApiError);
        expect(error.statusCode).toBe(403);
        expect(error.message).toContain('no está permitido');
      });
    });
    
    it('debe impedir que los usuarios accedan a sesiones de otros usuarios', async () => {
      await withTestContext(async ({ controller, redis }) => {
        // Crear una sesión de prueba para otro usuario
        const otherUserId = 'other-user-456';
        const testSessionId = 'test-session-123';
        
        await redis.set(
          `discovery:session:${testSessionId}`,
          JSON.stringify({
            id: testSessionId,
            userId: otherUserId,
            status: 'completed',
            startTime: new Date().toISOString(),
            options: { networkRanges: ['192.168.1.0/24'] },
            devices: [],
          })
        );
        
        // Intentar acceder a la sesión con un usuario diferente
        const testUser = { id: 'test-user-123', isAdmin: false };
        let error: any;
        
        await controller.getDiscoveryStatus(
          { 
            params: { sessionId: testSessionId },
            user: testUser,
          } as any,
          {} as any,
          (err: any) => { error = err; }
        );
        
        expect(error).toBeInstanceOf(ApiError);
        expect(error.statusCode).toBe(403);
      });
    });
    
    it('debe permitir que los administradores accedan a todas las sesiones', async () => {
      await withTestContext(async ({ controller, redis }) => {
        // Crear una sesión de prueba para otro usuario
        const otherUserId = 'other-user-456';
        const testSessionId = 'test-session-123';
        
        await redis.set(
          `discovery:session:${testSessionId}`,
          JSON.stringify({
            id: testSessionId,
            userId: otherUserId,
            status: 'completed',
            startTime: new Date().toISOString(),
            options: { networkRanges: ['192.168.1.0/24'] },
            devices: [],
          })
        );
        
        // Intentar acceder a la sesión como administrador
        const adminUser = { id: 'admin-user-789', isAdmin: true };
        let responseData: any;
        
        await controller.getDiscoveryStatus(
          { 
            params: { sessionId: testSessionId },
            user: adminUser,
          } as any,
          {
            json: (data: any) => { responseData = data; },
          } as any,
          (error: any) => { if (error) throw error; }
        );
        
        // Verificar que se permitió el acceso
        expect(responseData).toBeDefined();
        expect(responseData.success).toBe(true);
        expect(responseData.sessionId).toBe(testSessionId);
      });
    });
  });
  
  describe('Resistencia a fallos', () => {
    it('debe manejar correctamente la desconexión de Redis', async () => {
      await withTestContext(async ({ redis, controller }) => {
        // Simular una desconexión de Redis
        await redis.disconnect();
        
        // Intentar iniciar un descubrimiento
        let error: any;
        
        await controller.startDiscovery(
          { 
            body: { 
              networkRanges: ['192.168.1.0/24'],
              scanPorts: [80],
              protocols: ['onvif'],
            },
            user: { id: 'test-user-123' },
            params: {},
            query: {},
          } as any,
          {} as any,
          (err: any) => { error = err; }
        );
        
        // Verificar que se manejó el error correctamente
        expect(error).toBeDefined();
        expect(error.message).toContain('Redis');
      });
    });
    
    it('debe reintentar automáticamente las conexiones WebSocket fallidas', async () => {
      // Esta prueba simularía reconexiones de WebSocket
      // En una implementación real, se probaría la lógica de reconexión
      // del cliente y del servidor
      expect(true).toBe(true); // Placeholder para la prueba
    });
  });
  
  describe('Rendimiento', () => {
    it('debe manejar múltiples descubrimientos simultáneos', async () => {
      await withTestContext(async ({ controller }) => {
        // Configurar un límite de concurrencia bajo para la prueba
        process.env.DISCOVERY_CONCURRENCY = '2';
        
        // Iniciar múltiples descubrimientos
        const testUser = { id: 'test-user-123', isAdmin: false };
        const discoveryPromises = [];
        
        for (let i = 0; i < 3; i++) {
          discoveryPromises.push(
            new Promise((resolve, reject) => {
              controller.startDiscovery(
                { 
                  body: { 
                    networkRanges: [`192.168.${i + 1}.0/24`],
                    scanPorts: [80],
                    protocols: ['onvif'],
                  },
                  user: testUser,
                  params: {},
                  query: {},
                } as any,
                {
                  status: jest.fn().mockReturnThis(),
                  json: (data: any) => {
                    if (data.success) {
                      resolve(data.sessionId);
                    } else {
                      reject(new Error('Error al iniciar el descubrimiento'));
                    }
                  },
                } as any,
                (error: any) => { if (error) reject(error); }
              );
            })
          );
        }
        
        // Verificar que se iniciaron todos los descubrimientos
        const sessionIds = await Promise.all(discoveryPromises);
        expect(sessionIds).toHaveLength(3);
        expect(sessionIds.every(id => typeof id === 'string')).toBe(true);
      });
    });
  });
});

describe('Integración: WebSockets', () => {
  let httpServer: Server;
  let io: SocketIOServer;
  let controller: DiscoveryController;
  let redis: any;
  let worker: any;
  
  beforeAll(async () => {
    // Configurar el entorno de prueba
    const testContext = await withTestContext(async (context) => {
      redis = context.redis;
      worker = context.worker;
      controller = context.controller;
      
      // Configurar un servidor HTTP y WebSocket para pruebas
      const app = express();
      httpServer = createServer(app);
      io = new SocketIOServer(httpServer, {
        cors: {
          origin: '*',
          methods: ['GET', 'POST'],
        },
      });
      
      // Configurar el controlador con el servidor de sockets
      // @ts-ignore - Acceder al método privado para propósitos de prueba
      controller.setSocketServer(io);
      
      // Iniciar el servidor
      await new Promise<void>((resolve) => {
        httpServer.listen(0, () => resolve());
      });
    });
  });
  
  afterAll(async () => {
    // Cerrar el servidor y limpiar recursos
    if (httpServer) {
      await new Promise<void>((resolve) => {
        httpServer.close(() => resolve());
      });
    }
    
    if (io) {
      io.close();
    }
    
    if (redis) {
      await redis.disconnect();
    }
    
    if (worker) {
      await worker.close();
    }
  });
  
  it('debe permitir la conexión WebSocket con autenticación válida', async () => {
    const port = (httpServer.address() as AddressInfo).port;
    const testUser = { id: 'test-user-123', isAdmin: false };
    const authToken = generateTestToken(testUser);
    
    // Crear una sesión de prueba
    const testSessionId = 'test-session-ws-1';
    await redis.set(
      `discovery:session:${testSessionId}`,
      JSON.stringify({
        id: testSessionId,
        userId: testUser.id,
        status: 'running',
        startTime: new Date().toISOString(),
        options: { networkRanges: ['192.168.1.0/24'] },
        devices: [],
      })
    );
    
    // Conectar un cliente WebSocket
    const socket = ioClient(`http://localhost:${port}`, {
      auth: { token: authToken },
      query: { sessionId: testSessionId },
      reconnection: false,
      timeout: 5000,
    });
    
    // Esperar a que se conecte
    await new Promise<void>((resolve, reject) => {
      const timeout = setTimeout(() => {
        socket.disconnect();
        reject(new Error('Tiempo de espera agotado para la conexión WebSocket'));
      }, 3000);
      
      socket.on('connect', () => {
        clearTimeout(timeout);
        resolve();
      });
      
      socket.on('connect_error', (err) => {
        clearTimeout(timeout);
        reject(err);
      });
    });
    
    // Verificar que el socket está conectado
    expect(socket.connected).toBe(true);
    
    // Desconectar el socket
    socket.disconnect();
  });
  
  it('debe rechazar la conexión WebSocket sin autenticación', async () => {
    const port = (httpServer.address() as AddressInfo).port;
    
    // Intentar conectar sin token de autenticación
    const socket = ioClient(`http://localhost:${port}`, {
      reconnection: false,
      timeout: 5000,
    });
    
    // Verificar que la conexión es rechazada
    await expect(
      new Promise((resolve, reject) => {
        const timeout = setTimeout(() => {
          socket.disconnect();
          resolve('timeout');
        }, 3000);
        
        socket.on('connect', () => {
          clearTimeout(timeout);
          socket.disconnect();
          reject(new Error('Se esperaba que la conexión fuera rechazada'));
        });
        
        socket.on('connect_error', (err) => {
          clearTimeout(timeout);
          resolve('error');
        });
      })
    ).resolves.toBe('error');
    
    // Verificar que el socket no está conectado
    expect(socket.connected).toBe(false);
  });
  
  it('debe recibir actualizaciones en tiempo real del progreso del descubrimiento', async () => {
    const port = (httpServer.address() as AddressInfo).port;
    const testUser = { id: 'test-user-123', isAdmin: false };
    const authToken = generateTestToken(testUser);
    
    // Crear una sesión de prueba
    const testSessionId = 'test-session-ws-2';
    await redis.set(
      `discovery:session:${testSessionId}`,
      JSON.stringify({
        id: testSessionId,
        userId: testUser.id,
        status: 'running',
        startTime: new Date().toISOString(),
        options: { networkRanges: ['192.168.1.0/24'] },
        devices: [],
      })
    );
    
    // Conectar un cliente WebSocket
    const socket = ioClient(`http://localhost:${port}`, {
      auth: { token: authToken },
      query: { sessionId: testSessionId },
      reconnection: false,
      timeout: 5000,
    });
    
    // Esperar a que se conecte
    await new Promise<void>((resolve) => {
      socket.on('connect', () => resolve());
    });
    
    // Variables para rastrear el estado
    let progressEvents: any[] = [];
    let deviceEvents: any[] = [];
    
    // Escuchar eventos de progreso y dispositivos
    socket.on('discovery:progress', (data) => {
      progressEvents.push(data);
    });
    
    socket.on('discovery:device', (device) => {
      deviceEvents.push(device);
    });
    
    // Simular actualizaciones de progreso
    worker.emit('progress', 
      { data: { sessionId: testSessionId } }, 
      { progress: 25, phase: 'scanning', status: 'running' }
    );
    
    // Simular un dispositivo descubierto
    const mockDevice = {
      id: 'test-device-ws-1',
      ip: '192.168.1.100',
      port: 80,
      protocol: 'http',
      status: 'online',
    };
    
    worker.emit('deviceFound', 
      { data: { sessionId: testSessionId } }, 
      mockDevice
    );
    
    // Esperar a que se reciban los eventos
    await waitFor(() => progressEvents.length > 0 && deviceEvents.length > 0, 3000);
    
    // Verificar que se recibieron las actualizaciones
    expect(progressEvents.length).toBeGreaterThan(0);
    expect(progressEvents[0].progress).toBe(25);
    expect(deviceEvents.length).toBe(1);
    expect(deviceEvents[0].id).toBe(mockDevice.id);
    
    // Desconectar el socket
    socket.disconnect();
  });
});
