// Set up mocks before any imports that might use the database

// Define our own types to avoid conflicts with @types/pg
interface MockQueryResult<T = any> {
  command: string;
  rowCount: number | null;  // Changed to match pg's QueryResult
  oid: number | null;       // Made nullable to match pg's QueryResult
  fields: any[];
  rows: T[];
}

// Create a factory for mock query results
const createMockQueryResult = <T = any>(rows: T[] = [], rowCount: number | null = null): MockQueryResult<T> => ({
  command: '',
  rowCount: rowCount ?? rows.length,
  oid: null,
  fields: [],
  rows
});

// Mock implementation of PoolClient
class MockPoolClientImpl {
  query = jest.fn(async (query: string, params?: any[]): Promise<MockQueryResult> => 
    createMockQueryResult()
  );
  
  release = jest.fn((err?: Error | boolean): void => {});
  
  // Add any other required PoolClient methods
  on = jest.fn();
  removeListener = jest.fn();
  queryStream = jest.fn();
  copyFrom = jest.fn();
  copyTo = jest.fn();
  pauseDrain = jest.fn();
  resumeDrain = jest.fn();
  escapeIdentifier = jest.fn();
  escapeLiteral = jest.fn();
  
  // Internal properties that might be accessed
  _types: any = {};
  _pulseQueryQueue = () => {};
  _query: any = {};
  _events: any = {};
  
  // Add any other properties that might be accessed
  [key: string]: any;
}

// Create mock client instance
const mockClient = new MockPoolClientImpl();

// Mock connect function
const mockConnect = jest.fn().mockImplementation(async () => mockClient);

// Mock the database module with proper typing
jest.mock('../../../src/services/database', () => ({
  __esModule: true,
  default: {
    query: mockClient.query,
    getClient: mockConnect,
    end: jest.fn()
  }
}));

// Mock the pg module with proper typing
jest.mock('pg', () => ({
  Pool: jest.fn(() => ({
    query: mockClient.query,
    connect: mockConnect,
    end: jest.fn()
  }))
}));

// Now import the modules that use the database
import { jest } from '@jest/globals';
import { Request, Response, NextFunction } from 'express';
import { PoolClient, QueryResult } from 'pg';
import * as bcrypt from 'bcryptjs';
import * as jwt from 'jsonwebtoken';
import { AuthController } from '../../../src/controllers/authController';
import { db } from '../../../src/services/database';

// Mock bcrypt
jest.mock('bcryptjs');
const mockBcrypt = bcrypt as jest.Mocked<typeof bcrypt>;

// Mock jsonwebtoken
jest.mock('jsonwebtoken');
const mockJwt = jwt as jest.Mocked<typeof jwt>;

// Mock email service
jest.mock('../../../src/services/emailService', () => ({
  sendVerificationEmail: jest.fn().mockResolvedValue(undefined),
  sendPasswordResetEmail: jest.fn().mockResolvedValue(undefined)
}));

// Import email service after mocking
import * as emailService from '../../../src/services/emailService';
const mockEmailService = emailService as jest.Mocked<typeof emailService>;

// Helper function to create a mock request
const createMockRequest = (overrides: Partial<Request> = {}): Request => {
  const req = {
    body: {},
    cookies: {},
    params: {},
    query: {},
    user: undefined,
    ...overrides,
    // Add required Express request methods
    get: jest.fn(),
    header: jest.fn()
  } as unknown as Request;
  
  return req;
};

// Helper function to create a mock response
const createMockResponse = (): Response => {
  const res: any = {};
  
  // Chainable methods
  [
    'status', 'json', 'send', 'sendStatus', 'redirect', 'cookie', 
    'clearCookie', 'append', 'attachment', 'download', 'end', 
    'format', 'jsonp', 'links', 'location', 'render', 'sendFile',
    'set', 'type', 'vary'
  ].forEach(method => {
    res[method] = jest.fn().mockReturnThis();
  });
  
  // Other methods
  res.get = jest.fn();
  res.getHeader = jest.fn();
  
  // Properties
  res.locals = {};
  
  return res as Response;
};

describe('AuthController', () => {
  let authController: AuthController;
  let mockReq: Request;
  let mockRes: Response;
  let mockNext: NextFunction;
  let mockClient: jest.Mocked<PoolClient>;

  beforeEach(() => {
    // Reset all mocks before each test
    jest.clearAllMocks();
    
    // Create fresh instances for each test
    authController = new AuthController();
    mockReq = createMockRequest();
    mockRes = createMockResponse();
    mockNext = jest.fn();
    
    // Setup mock database client with proper typing
    mockClient = new MockPoolClientImpl() as unknown as jest.Mocked<PoolClient>;
    
    // Mock the database connection
    mockConnect.mockResolvedValue(mockClient);
    
    // Mock database queries with proper typing
    (mockClient.query as jest.Mock).mockImplementation(async (query: string, params: any[] = []): Promise<QueryResult> => {
      // Handle user existence check
      if (query.includes('SELECT * FROM users WHERE email')) {
        return Promise.resolve({ 
          rowCount: 0, 
          rows: [], 
          command: 'SELECT', 
          oid: 0, 
          fields: [] 
        } as QueryResult);
      }
      
      // Handle user creation
      if (query.includes('INSERT INTO users')) {
        return Promise.resolve({
          rowCount: 1,
          rows: [{
            id: 'user123',
            email: params?.[0] || 'test@example.com',
            name: params?.[1] || 'Test User',
            password_hash: params?.[2] || 'hashedPassword',
            verification_token: params?.[3] || 'test-verification-token',
            verification_token_expires: new Date(Date.now() + 24 * 60 * 60 * 1000),
            is_verified: params?.[4] || false,
            created_at: new Date(),
            updated_at: new Date()
          }],
          command: 'INSERT',
          oid: 1,
          fields: []
        } as QueryResult);
      }
      
      // Default response for any other queries
      return Promise.resolve({ 
        rowCount: 0, 
        rows: [], 
        command: '', 
        oid: 0, 
        fields: [] 
      } as QueryResult);
    });
    
        // Mock bcrypt functions
    jest.spyOn(mockBcrypt, 'genSalt').mockImplementation(() => Promise.resolve('salt'));
    jest.spyOn(mockBcrypt, 'hash').mockImplementation(() => Promise.resolve('hashedPassword'));
    jest.spyOn(mockBcrypt, 'compare').mockImplementation(() => Promise.resolve(true));
    
    // Mock JWT functions
    jest.spyOn(mockJwt, 'sign').mockReturnValue('mocked-jwt-token');
    jest.spyOn(mockJwt, 'verify').mockImplementation(() => ({
      userId: 'user123',
      email: 'test@example.com',
      type: 'access'
    }));
  });

  describe('register', () => {
    it('should register a new user', async () => {
      // Arrange
      mockReq.body = {
        email: 'test@example.com',
        password: 'password123',
        name: 'Test User'
      };
      
      // Mock the first query (check if user exists)
    (mockClient.query as jest.Mock).mockImplementationOnce(async (query: string) => ({
      rowCount: 0,
      rows: [],
      command: 'SELECT',
      oid: 0,
      fields: []
    } as QueryResult));
    
    // Mock the second query (insert new user)
    (mockClient.query as jest.Mock).mockImplementationOnce(async (query: string) => ({
      rowCount: 1,
      rows: [{
        id: 'user123',
        email: 'test@example.com',
        name: 'Test User',
        is_admin: false,
        is_verified: false,
        created_at: new Date(),
        updated_at: new Date()
      }],
      command: 'INSERT',
      oid: 0,
      fields: []
    } as QueryResult));
      
      // Mock the email service
      jest.spyOn(mockEmailService, 'sendVerificationEmail').mockResolvedValue({
        messageId: 'test-message-id'
      });
      
      // Act
      await authController.register(mockReq, mockRes, mockNext);
      
      // Assert
      expect(mockConnect).toHaveBeenCalledTimes(1);
      
      // Verify the first query (check if user exists)
      expect(mockClient.query).toHaveBeenNthCalledWith(
        1,
        'SELECT id FROM users WHERE email = $1',
        ['test@example.com']
      );
      
      // Verify the second query (insert new user)
      expect(mockClient.query).toHaveBeenNthCalledWith(
        2,
        `INSERT INTO users (\n          email, \n          name, \n          password_hash, \n          verification_token,\n          verification_token_expires,\n          is_verified\n        ) VALUES ($1, $2, $3, $4, NOW() + INTERVAL '24 hours', $5)\n        RETURNING *`,
        [
          'test@example.com',
          'Test User',
          'hashedPassword',
          expect.any(String), // hashed verification token
          false
        ]
      );
      
      expect(mockBcrypt.genSalt).toHaveBeenCalledWith(10);
      expect(mockBcrypt.hash).toHaveBeenCalledWith('password123', 'salt');
      expect(mockClient.release).toHaveBeenCalledTimes(1);
      expect(mockEmailService.sendVerificationEmail).toHaveBeenCalledWith(
        'Test User',
        'test@example.com',
        expect.any(String)
      );
      expect(mockRes.status).toHaveBeenCalledWith(201);
      expect(mockRes.json).toHaveBeenCalledWith(expect.objectContaining({
        message: 'User registered successfully. Please check your email to verify your account.'
      }));
    });
    
    // Add more test cases for registration
  });
  
  // Add more test suites for other controller methods
});
