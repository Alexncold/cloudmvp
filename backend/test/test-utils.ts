import { Server } from 'http';
import { AddressInfo } from 'net';
import express, { Express } from 'express';
import { createClient, RedisClientType } from 'redis';
import { Worker } from 'bullmq';
import { Server as SocketIOServer } from 'socket.io';
import { io as ioClient, Socket } from 'socket.io-client';
import { DiscoveryController } from '../src/controllers/discoveryController';
import { ApiError } from '../src/utils/errors';

// Tipos para las utilidades de prueba
type TestServer = {
  app: Express;
  server: Server;
  port: number;
  close: () => Promise<void>;
};

type TestRedisClient = RedisClientType & {
  cleanup: () => Promise<void>;
};

type TestWorker = Worker & {
  close: () => Promise<void>;
};

type TestSocketClient = Socket & {
  disconnect: () => Promise<void>;
};

// Configuración de prueba
export const TEST_CONFIG = {
  REDIS_URL: process.env.TEST_REDIS_URL || 'redis://localhost:6379',
  TEST_USER: {
    id: 'test-user-123',
    email: 'test@example.com',
    isAdmin: false,
  },
  TEST_ADMIN: {
    id: 'test-admin-456',
    email: 'admin@example.com',
    isAdmin: true,
  },
  ALLOWED_NETWORK_RANGES: ['192.168.1.0/24', '10.0.0.0/8'],
};

/**
 * Crea un servidor Express de prueba con autenticación simulada
 */
export const createTestServer = async (): Promise<TestServer> => {
  const app = express();
  const server = new Server(app);
  
  // Middleware para simular autenticación
  app.use((req, res, next) => {
    // Simular un usuario autenticado para las pruebas
    req.user = { ...TEST_CONFIG.TEST_USER };
    next();
  });
  
  // Iniciar el servidor en un puerto aleatorio
  return new Promise((resolve) => {
    server.listen(0, () => {
      const address = server.address() as AddressInfo;
      const port = address.port;
      
      // Método para cerrar el servidor
      const close = async () => {
        return new Promise<void>((resolveClose) => {
          server.close(() => resolveClose());
        });
      };
      
      resolve({ app, server, port, close });
    });
  });
};

/**
 * Crea un cliente Redis de prueba con un espacio de nombres único
 */
export const createTestRedisClient = async (): Promise<TestRedisClient> => {
  const testId = `test-${Date.now()}`;
  const client = createClient({
    url: TEST_CONFIG.REDIS_URL,
    socket: {
      reconnectStrategy: (retries) => {
        if (retries > 3) {
          throw new Error('Demasiados intentos de reconexión a Redis');
        }
        return 100; // 100ms de retraso entre intentos
      },
    },
  }) as TestRedisClient;
  
  await client.connect();
  
  // Limpiar datos de pruebas anteriores
  client.cleanup = async () => {
    // Eliminar todas las claves del espacio de nombres de prueba
    const keys = await client.keys(`${testId}:*`);
    if (keys.length > 0) {
      await client.del(keys);
    }
  };
  
  // Sobrescribir métodos para usar el espacio de nombres de prueba
  const originalSet = client.set.bind(client);
  (client as any).set = (key: string, value: string, options?: any) => {
    return originalSet(`${testId}:${key}`, value, options);
  };
  
  const originalGet = client.get.bind(client);
  (client as any).get = (key: string) => {
    return originalGet(`${testId}:${key}`);
  };
  
  const originalDel = client.del.bind(client);
  (client as any).del = (key: string | string[]) => {
    const keys = Array.isArray(key) 
      ? key.map(k => `${testId}:${k}`) 
      : `${testId}:${key}`;
    return originalDel(keys as any);
  };
  
  const originalHSet = client.hSet.bind(client);
  (client as any).hSet = (key: string, field: string, value: string) => {
    return originalHSet(`${testId}:${key}`, field, value);
  };
  
  const originalHGetAll = client.hGetAll.bind(client);
  (client as any).hGetAll = (key: string) => {
    return originalHGetAll(`${testId}:${key}`);
  };
  
  const originalMulti = client.multi.bind(client);
  (client as any).multi = () => {
    const multi = originalMulti();
    
    // Interceptar comandos para agregar el prefijo de prueba
    const originalExec = multi.exec.bind(multi);
    multi.exec = async () => {
      // Aplicar prefijo a todas las claves en los comandos
      const commands = (multi as any).queue;
      for (const cmd of commands) {
        if (cmd.name === 'set' || cmd.name === 'get' || cmd.name === 'del' || 
            cmd.name === 'hset' || cmd.name === 'hgetall') {
          cmd.args[0] = `${testId}:${cmd.args[0]}`;
        }
      }
      
      return originalExec();
    };
    
    return multi;
  };
  
  return client;
};

/**
 * Crea un worker de prueba para colas
 */
export const createTestWorker = async (redisClient: RedisClientType): Promise<TestWorker> => {
  const worker = new Worker('test-queue', async () => {}, {
    connection: {
      ...redisClient.options.socket,
      host: new URL(TEST_CONFIG.REDIS_URL).hostname,
      port: parseInt(new URL(TEST_CONFIG.REDIS_URL).port || '6379', 10),
    },
  }) as TestWorker;
  
  worker.close = async () => {
    await worker.close(true);
  };
  
  return worker;
};

/**
 * Crea un cliente de socket de prueba conectado al servidor
 */
export const createTestSocketClient = async (
  server: Server, 
  options: { authToken?: string; query?: Record<string, string> } = {}
): Promise<TestSocketClient> => {
  const io = new SocketIOServer(server);
  
  return new Promise((resolve, reject) => {
    const socket = ioClient(`http://localhost:${(server.address() as AddressInfo).port}`, {
      auth: options.authToken ? { token: options.authToken } : undefined,
      query: options.query,
      reconnection: false,
      timeout: 5000,
    }) as TestSocketClient;
    
    socket.on('connect', () => {
      // Agregar método de desconexión mejorado
      const originalDisconnect = socket.disconnect.bind(socket);
      socket.disconnect = () => {
        return new Promise<void>((resolveDisconnect) => {
          originalDisconnect();
          socket.on('disconnect', () => resolveDisconnect());
        });
      };
      
      resolve(socket);
    });
    
    socket.on('connect_error', (err) => {
      reject(new Error(`Error de conexión del socket: ${err.message}`));
    });
  });
};

/**
 * Espera a que se complete una condición o se agote el tiempo de espera
 */
export const waitFor = async (
  condition: () => boolean | Promise<boolean>, 
  timeout = 5000,
  interval = 100
): Promise<boolean> => {
  const startTime = Date.now();
  
  while (Date.now() - startTime < timeout) {
    const result = await Promise.resolve(condition());
    if (result) return true;
    await new Promise(resolve => setTimeout(resolve, interval));
  }
  
  return false;
};

/**
 * Ejecuta una prueba con un contexto de prueba limpio
 */
export const withTestContext = async (
  testFn: (context: {
    redis: TestRedisClient;
    worker: TestWorker;
    server: TestServer;
    controller: DiscoveryController;
  }) => Promise<void>,
  options: { withServer?: boolean } = {}
) => {
  let redis: TestRedisClient | null = null;
  let worker: TestWorker | null = null;
  let server: TestServer | null = null;
  let controller: DiscoveryController | null = null;
  
  try {
    // Configurar Redis
    redis = await createTestRedisClient();
    
    // Configurar worker
    worker = await createTestWorker(redis);
    
    // Configurar servidor si es necesario
    if (options.withServer) {
      server = await createTestServer();
    }
    
    // Configurar controlador con dependencias de prueba
    controller = DiscoveryController.getInstance();
    
    // Ejecutar la prueba
    await testFn({ redis, worker, server, controller } as any);
  } finally {
    // Limpiar recursos
    const cleanupPromises = [];
    
    if (worker) {
      cleanupPromises.push(worker.close());
    }
    
    if (redis) {
      cleanupPromises.push(redis.cleanup().then(() => redis!.disconnect()));
    }
    
    if (server) {
      cleanupPromises.push(server.close());
    }
    
    await Promise.all(cleanupPromises);
  }
};

/**
 * Genera un token JWT de prueba
 */
export const generateTestToken = (user: { id: string; isAdmin?: boolean }): string => {
  // En un entorno real, esto firmaría un token JWT válido
  // Para pruebas, devolvemos un token simulado
  const payload = {
    sub: user.id,
    email: `${user.id}@test.com`,
    isAdmin: user.isAdmin || false,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 3600, // 1 hora de expiración
  };
  
  // Codificar el payload en base64 para simular un token JWT
  const encodedPayload = Buffer.from(JSON.stringify(payload)).toString('base64');
  return `test.${encodedPayload}.signature`;
};

/**
 * Middleware de autenticación de prueba
 */
export const testAuthMiddleware = (req: any, res: any, next: any) => {
  // Simular autenticación para pruebas
  const authHeader = req.headers.authorization;
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return next(new ApiError('No autorizado', 401));
  }
  
  const token = authHeader.split(' ')[1];
  
  try {
    // En un entorno real, esto verificaría un token JWT válido
    // Para pruebas, simplemente extraemos el ID de usuario del token simulado
    const payload = JSON.parse(
      Buffer.from(token.split('.')[1], 'base64').toString()
    );
    
    req.user = {
      id: payload.sub,
      email: payload.email,
      isAdmin: payload.isAdmin || false,
    };
    
    next();
  } catch (error) {
    next(new ApiError('Token inválido', 401));
  }
};
