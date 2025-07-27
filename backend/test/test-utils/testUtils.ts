import { Request, Response, NextFunction } from 'express';
import { v4 as uuidv4 } from 'uuid';
import jwt from 'jsonwebtoken';
import { db } from '../../src/services/db';
import { logger } from '../../src/utils/logger';
import testConfig from './testConfig';

// Types for utility functions
type MockRequest = Partial<Request> & {
  user?: any;
  headers: Record<string, string>;
  body: Record<string, any>;
  params: Record<string, string>;
  query: Record<string, any>;
  get: (name: string) => string | undefined;
};

type MockResponse = Partial<Response> & {
  status: jest.Mock;
  json: jest.Mock;
  send: jest.Mock;
  redirect: jest.Mock;
  setHeader: jest.Mock;
};

/**
 * Creates a mock request object for testing
 */
export const createMockRequest = (options: Partial<MockRequest> = {}): MockRequest => {
  const headers: Record<string, string> = {
    'user-agent': 'jest-test',
    'x-forwarded-for': '127.0.0.1',
    ...options.headers,
  };

  return {
    headers,
    body: {},
    params: {},
    query: {},
    ip: '127.0.0.1',
    method: 'GET',
    originalUrl: '/',
    ...options,
    get: function (name: string): string | undefined {
      return this.headers[name.toLowerCase()];
    },
  } as MockRequest;
};

/**
 * Creates a mock response object for testing
 */
export const createMockResponse = (): MockResponse => {
  const res: any = {};
  res.status = jest.fn().mockReturnValue(res);
  res.json = jest.fn().mockReturnValue(res);
  res.send = jest.fn().mockReturnValue(res);
  res.redirect = jest.fn().mockReturnValue(res);
  res.setHeader = jest.fn().mockReturnValue(res);
  res.clearCookie = jest.fn().mockReturnValue(res);
  res.cookie = jest.fn().mockReturnValue(res);
  return res as MockResponse;
};

/**
 * Creates a mock next function for testing
 */
export const createMockNext = (): jest.Mock => {
  return jest.fn();
};

/**
 * Generates a JWT token for testing
 */
export const generateTestToken = (
  payload: any = {},
  expiresIn: string = '1h',
  secret: string = testConfig.auth.jwtSecret
): string => {
  return jwt.sign(
    {
      userId: uuidv4(),
      email: 'test@example.com',
      role: 'user',
      ...payload,
    },
    secret,
    { expiresIn }
  );
};

/**
 * Creates an authenticated request with a valid JWT token
 */
export const createAuthenticatedRequest = (
  user: any = { id: 'test-user-id', role: 'user' },
  options: Partial<MockRequest> = {}
): MockRequest => {
  const token = generateTestToken(user);
  return createMockRequest({
    ...options,
    headers: {
      ...options.headers,
      authorization: `Bearer ${token}`,
    },
    user,
  });
};

/**
 * Resets the test database
 */
export const resetTestDatabase = async (): Promise<void> => {
  try {
    // Get all tables in the public schema
    const result = await db.query(
      `SELECT tablename 
       FROM pg_tables 
       WHERE schemaname = 'public'`
    );
    
    const tables = result.rows.map(row => row.tablename);
    
    // Truncate all tables (except migration tables)
    for (const table of tables) {
      if (!table.startsWith('_')) { // Skip migration tables
        await db.query(`TRUNCATE TABLE "${table}" CASCADE`);
      }
    }
    
    // Reset sequences
    const sequences = await db.query(
      `SELECT c.relname 
       FROM pg_class c 
       WHERE c.relkind = 'S'`
    );
    
    for (const seq of sequences.rows) {
      await db.query(`ALTER SEQUENCE "${seq.relname}" RESTART WITH 1`);
    }
    
    logger.info('Test database reset');
  } catch (error) {
    logger.error('Error resetting test database', { error });
    throw error;
  }
};

/**
 * Wraps a test function in a transaction
 */
export const withTestTransaction = (fn: () => Promise<void>): (() => Promise<void>) => {
  return async () => {
    // Start transaction
    await db.query('BEGIN');
    
    try {
      // Execute test function
      await fn();
      // Rollback changes when done
      await db.query('ROLLBACK');
    } catch (error) {
      // Ensure changes are rolled back on error
      await db.query('ROLLBACK');
      throw error;
    }
  };
};

/**
 * Sets up the test environment
 */
export const setupTestEnvironment = async (): Promise<void> => {
  // Set test environment variables
  process.env.NODE_ENV = 'test';
  
  // Configure logger for tests
  logger.silent = true; // Suppress logs during tests
  
  // Verify database connection
  try {
    await db.query('SELECT 1');
    logger.info('Test database connection established');
  } catch (error) {
    logger.error('Failed to connect to test database', { error });
    throw error;
  }
};

/**
 * Cleans up the test environment
 */
export const teardownTestEnvironment = async (): Promise<void> => {
  // Restore logger configuration
  logger.silent = false;
  
  // Close database connection
  try {
    await db.end();
    logger.info('Database connection closed');
  } catch (error) {
    logger.error('Error closing database connection', { error });
  }
};

/**
 * Mocks the authentication middleware for testing
 */
export const mockAuthMiddleware = (user: any = { id: 'test-user-id', role: 'user' }) => {
  return (req: any, res: any, next: NextFunction) => {
    req.user = { ...user };
    next();
  };
};

/**
 * Mocks the admin middleware for testing
 */
export const mockAdminMiddleware = (req: any, res: any, next: NextFunction) => {
  req.user = { role: 'admin', id: 'admin-user-id' };
  next();
};

/**
 * Creates a test user in the database
 */
export const createTestUser = async (userData: any = {}) => {
  const defaultUser = {
    email: `test-${uuidv4()}@example.com`,
    password: 'TestPassword123!',
    name: 'Test User',
    is_verified: true,
    ...userData,
  };

  const result = await db.query(
    `INSERT INTO users (email, password_hash, name, is_verified)
     VALUES ($1, $2, $3, $4)
     RETURNING id, email, name, is_verified`,
    [defaultUser.email, defaultUser.password, defaultUser.name, defaultUser.is_verified]
  );

  return result.rows[0];
};

/**
 * Asserts that a route is protected
 */
export const expectRouteToBeProtected = async (
  request: () => Promise<any>,
  expectedStatus: number = 401
) => {
  try {
    const response = await request();
    // If we get here, the route didn't return an error as expected
    expect(response.status).toBe(expectedStatus);
  } catch (error: any) {
    // For some HTTP clients, errors are thrown for non-2xx status codes
    if (error.response) {
      expect(error.response.status).toBe(expectedStatus);
    } else {
      throw error;
    }
  }
};

/**
 * Asserts that a route requires admin privileges
 */
export const expectRouteToRequireAdmin = async (
  request: () => Promise<any>,
  userToken: string
) => {
  try {
    const response = await request();
    // If we get here, the route didn't return a 403 as expected
    expect(response.status).toBe(403);
  } catch (error: any) {
    if (error.response) {
      expect(error.response.status).toBe(403);
    } else {
      throw error;
    }
  }
};
