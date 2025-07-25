// Configuración de pruebas
import dotenv from 'dotenv';
import path from 'path';
import { jest } from '@jest/globals';
import type { Config } from '@jest/types';
import { createServer } from 'http';
import createApp from '../src/app';
import { Server } from 'http';
import { AddressInfo } from 'net';

// Extender el tipo global para incluir testRequest
declare global {
  // eslint-disable-next-line no-var
  var testRequest: import('supertest').SuperTest<import('supertest').Test>;
  // eslint-disable-next-line no-var
  var __COUNTER__: number;
  // eslint-disable-next-line no-var
  var __TEST_SERVER__: Server;
}

// Inicializar contador para tests
global.__COUNTER__ = 0;

// Cargar variables de entorno de prueba
const envPath = path.resolve(__dirname, '../.env.test');
dotenv.config({ path: envPath, override: true });

// Configuración global para las pruebas
global.console = {
  ...console,
  // Sobrescribir console.log para evitar ruido en las pruebas
  log: jest.fn(),
  info: jest.fn(),
  // Mantener console.error para ver errores
  error: jest.fn(console.error),
  warn: jest.fn(console.warn),
  debug: jest.fn(console.debug),
};

// Configurar el entorno de prueba
process.env.NODE_ENV = 'test';
process.env.PORT = '3002'; // Usar un puerto diferente para pruebas

// Import the mock database service for integration tests
import { db as mockDb } from './__mocks__/db';

// Configure the mock database for testing
beforeEach(() => {
  // Clear all mocks before each test
  jest.clearAllMocks();
  
  // Only configure integration test mocks if we're running integration tests
  if (process.env.TEST_TYPE === 'integration') {
    // Clear mock database
    mockDb.clearMocks();
    
    // Set up default mock responses for common queries
    mockDb.setMockResponse(
      'SELECT * FROM users WHERE email = $1',
      { rows: [], rowCount: 0 }
    );
    
    mockDb.setMockResponse(
      'INSERT INTO users (email, password, name, verification_token, verification_token_expires) VALUES ($1, $2, $3, $4, $5) RETURNING id, email, name, is_verified',
      {
        rows: [{
          id: 'test-user-id',
          email: 'test@example.com',
          name: 'Test User',
          is_verified: false
        }],
        rowCount: 1
      }
    );
  }
});

// Configuración adicional para las pruebas
beforeAll(async () => {
  // Iniciar el servidor antes de todas las pruebas
  const app = await createApp();
  global.__TEST_SERVER__ = createServer(app);
  await new Promise<void>((resolve) => {
    global.__TEST_SERVER__.listen(3002, '0.0.0.0', () => {
      console.log('Test server running on port 3002');
      resolve();
    });
  });
});

afterAll(async () => {
  // Cerrar el servidor después de todas las pruebas
  if (global.__TEST_SERVER__) {
    await new Promise<void>((resolve) => {
      global.__TEST_SERVER__.close(() => {
        console.log('Test server closed');
        resolve();
      });
    });
  }
});

beforeEach(() => {
  // Incrementar contador de tests
  global.__COUNTER__ += 1;
  
  // Limpiar todos los mocks antes de cada prueba
  jest.clearAllMocks();
  
  // Configuración específica para cada prueba
  jest.spyOn(console, 'error').mockImplementation(() => {});
  jest.spyOn(console, 'warn').mockImplementation(() => {});
});

afterEach(async () => {
  // Limpieza después de cada prueba
  jest.restoreAllMocks();
});

afterAll(async () => {
  // Limpieza después de todas las pruebas
});
