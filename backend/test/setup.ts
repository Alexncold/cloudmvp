// Load test environment variables first
import dotenv from 'dotenv';
import path from 'path';

// Load test environment variables from .env.test file
const envFilePath = path.resolve(__dirname, '../.env.test');
dotenv.config({ path: envFilePath });

// Test configuration
import { jest } from '@jest/globals';
import type { Config } from '@jest/types';
import { createServer, Server } from 'http';
import { AddressInfo } from 'net';
import { PoolClient, QueryResult } from 'pg';
import createApp from '../src/app';
import { logger } from '../src/utils/logger';
import { __mockDb, __mockQuery, __mockConnect, __mockClose } from '../__mocks__/database';
import { db as mockDb } from './__mocks__/db';

// Type definitions for mock functions
type MockQueryFunction = (query: string, params?: unknown[]) => Promise<QueryResult>;
type MockConnectFunction = () => Promise<PoolClient>;

// Global type extensions
declare global {
  // eslint-disable-next-line no-var
  var testRequest: import('supertest').SuperTest<import('supertest').Test>;
  // eslint-disable-next-line no-var
  var __TEST_SERVER__: import('http').Server | null;
  // eslint-disable-next-line no-var
  var __COUNTER__: number;
  // eslint-disable-next-line no-var
  var __TEST_DB_CONNECTION__: import('pg').Pool | null;
}

// Initialize global counter
global.__COUNTER__ = 0;

// Load test environment variables
const envPath = path.resolve(__dirname, '../.env.test');
const envResult = dotenv.config({ path: envPath, override: true });

if (envResult.error) {
  logger.warn('No .env.test file found, using default test environment');
}

// Validate required environment variables
const requiredEnvVars = [
  'NODE_ENV',
  'DATABASE_URL',
  'JWT_SECRET',
  'JWT_EXPIRES_IN'
];

const missingVars = requiredEnvVars.filter(varName => !process.env[varName]);
if (missingVars.length > 0) {
  logger.warn(`Missing required environment variables: ${missingVars.join(', ')}`);
}

// Configure test environment
process.env.NODE_ENV = 'test';
// Usar el mismo puerto que el backend
process.env.PORT = '3001';

// Configure global console mocks
global.console = {
  ...console,
  log: jest.fn(),
  info: jest.fn(),
  error: jest.fn(console.error),
  warn: jest.fn(console.warn),
  debug: jest.fn(console.debug),
};

// Global test setup
beforeAll(async () => {
  // Initialize test server if needed
  if (process.env.TEST_TYPE === 'integration') {
    const app = await createApp();
    const server = createServer(app);
    await new Promise<void>((resolve) => {
      server.listen(0, () => {
        const { port } = server.address() as AddressInfo;
        process.env.TEST_SERVER_URL = `http://localhost:${port}`;
        global.__TEST_SERVER__ = server;
        resolve();
      });
    });
  }
});

// Global test teardown
afterAll(async () => {
  // No necesitamos cerrar el servidor ya que estamos usando el existente
  console.log('Test setup complete - using existing server');
  
  // Limpiar cualquier conexión de base de datos si es necesario
  if (global.__TEST_DB_CONNECTION__) {
    try {
      await global.__TEST_DB_CONNECTION__.end();
      console.log('Test database connection closed');
    } catch (error) {
      console.error('Error closing test database connection:', error);
    }
  }
});

// Reset all mocks and database state before each test
beforeEach(() => {
  jest.clearAllMocks();
  
    // Reset the mock database state with proper typing
  const mockQueryImplementation: MockQueryFunction = (query, params = []) => {
    return Promise.resolve({
      rows: [],
      rowCount: 0,
      command: '',
      oid: 0,
      fields: [],
    });
  };

  // Create a mock client with proper typing
  const mockClient = {
    query: mockQueryImplementation,
    release: jest.fn().mockImplementation(() => Promise.resolve()),
  };
  
  // Clear and set up the mocks with proper typing
  (__mockQuery as jest.MockedFunction<MockQueryFunction>).mockClear();
  (__mockQuery as jest.MockedFunction<MockQueryFunction>).mockImplementation(mockQueryImplementation);
  
  (__mockConnect as jest.MockedFunction<MockConnectFunction>).mockClear();
  (__mockConnect as jest.MockedFunction<MockConnectFunction>).mockResolvedValue(mockClient as unknown as PoolClient);
  
  // Configure integration test mocks if needed
  if (process.env.TEST_TYPE === 'integration') {
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
  // Usar el backend existente en el puerto 3001
  console.log('Using existing backend server on port 3001');
  // No iniciamos un nuevo servidor, usamos el que ya está corriendo
  global.__TEST_SERVER__ = null; // Marcamos que no estamos usando un servidor de prueba
});

afterAll(async () => {
  // No necesitamos cerrar ningún servidor ya que estamos usando el existente
  console.log('Test setup complete - using existing server');
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
