// Test setup
import { jest } from '@jest/globals';
import { Request, Response, NextFunction } from 'express';
import { PoolClient } from 'pg';
import * as bcrypt from 'bcryptjs';
import * as jwt from 'jsonwebtoken';
import { AuthController } from '../../../src/controllers/authController';
import { db } from '../../../src/services/database';

// Mock dependencies
// Mock database functions
const mockQuery = jest.fn() as jest.MockedFunction<typeof db.query>;
const mockClose = jest.fn() as jest.MockedFunction<typeof db.close>;
const mockConnect = jest.fn() as jest.MockedFunction<typeof db.connect>;

// Mock bcrypt functions
const mockHash = jest.spyOn(bcrypt, 'hash') as jest.Mock<Promise<string>>;
const mockCompare = jest.spyOn(bcrypt, 'compare') as jest.Mock<Promise<boolean>>;
const mockGenSalt = jest.spyOn(bcrypt, 'genSalt') as jest.Mock<Promise<string>>;

// Mock JWT functions
const mockJwtSign = jest.spyOn(jwt, 'sign') as jest.Mock<string>;
const mockJwtVerify = jest.spyOn(jwt, 'verify') as jest.Mock<{ userId: string; email: string; type: string }>;

// Mock email service
const mockSendVerificationEmail = jest.fn() as jest.Mock<Promise<void>>;
const mockSendPasswordResetEmail = jest.fn() as jest.Mock<Promise<void>>;

// Setup default mock implementations
mockHash.mockResolvedValue('hashedPassword');
mockCompare.mockResolvedValue(true);
mockGenSalt.mockResolvedValue('salt');
mockJwtSign.mockReturnValue('mocked-jwt-token');
mockJwtVerify.mockReturnValue({ 
  userId: 'user123', 
  email: 'test@example.com',
  type: 'access'
});
mockSendVerificationEmail.mockResolvedValue(undefined);
mockSendPasswordResetEmail.mockResolvedValue(undefined);

// Mock database module
jest.mock('../../../src/services/database', () => ({
  __esModule: true,
  db: {
    query: mockQuery,
    close: mockClose,
    connect: mockConnect
  }
}));

// Mock email service module
jest.mock('../../../src/services/emailService', () => ({
  sendVerificationEmail: mockSendVerificationEmail,
  sendPasswordResetEmail: mockSendPasswordResetEmail
}));

// Mock JWT error classes for testing
class TokenExpiredError extends Error {
  constructor() {
    super('Token expired');
    this.name = 'TokenExpiredError';
  }
}

class JsonWebTokenError extends Error {
  constructor() {
    super('Invalid token');
    this.name = 'JsonWebTokenError';
  }
}

// Mock JWT module with proper typing
jest.mock('jsonwebtoken', () => ({
  sign: mockJwtSign,
  verify: mockJwtVerify,
  TokenExpiredError,
  JsonWebTokenError
}));

// Helper function to create a mock request
const createMockRequest = (overrides = {}) => {
  const req: any = {
    body: {},
    cookies: {},
    params: {},
    query: {},
    user: undefined,
    ...overrides
  };
  
  // Add any required Express request methods
  req.get = jest.fn();
  req.header = jest.fn();
  
  return req as Request;
};

// Helper function to create a mock response
const createMockResponse = () => {
  const res: any = {};
  
  // Chainable methods
  const chainableMethods = [
    'status', 'json', 'send', 'sendStatus', 'redirect', 'cookie', 
    'clearCookie', 'append', 'attachment', 'download', 'end', 
    'format', 'jsonp', 'links', 'location', 'render', 'sendFile',
    'set', 'type', 'vary'
  ];
  
  // Make all chainable methods return 'this'
  chainableMethods.forEach(method => {
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
  let mockNext: jest.Mock;
  let mockClient: PoolClient;

  beforeEach(() => {
    // Reset all mocks before each test
    jest.clearAllMocks();
    
    // Setup default mock request and response
    mockReq = {
      body: {},
      cookies: {},
      params: {},
      query: {},
      user: undefined,
      // Add type assertions to match Express Request
      get: jest.fn(),
      header: jest.fn(),
      accepts: jest.fn(),
      acceptsCharsets: jest.fn(),
      acceptsEncodings: jest.fn(),
      acceptsLanguages: jest.fn(),
      is: jest.fn(),
      range: jest.fn(),
      app: { get: jest.fn() } as any,
      baseUrl: '',
      hostname: 'localhost',
      ip: '127.0.0.1',
      method: 'GET',
      originalUrl: '',
      path: '/',
      protocol: 'http',
      secure: false,
      signedCookies: {},
      stale: false,
      subdomains: [],
      xhr: false
    } as unknown as Request;

    mockRes = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn().mockReturnThis(),
      cookie: jest.fn().mockReturnThis(),
      clearCookie: jest.fn().mockReturnThis(),
      // Add type assertions to match Express Response
      append: jest.fn().mockReturnThis(),
      attachment: jest.fn().mockReturnThis(),
      download: jest.fn().mockReturnThis(),
      end: jest.fn().mockReturnThis(),
      format: jest.fn().mockReturnThis(),
      get: jest.fn(),
      getHeader: jest.fn(),
      jsonp: jest.fn().mockReturnThis(),
      links: jest.fn().mockReturnThis(),
      location: jest.fn().mockReturnThis(),
      redirect: jest.fn().mockReturnThis(),
      render: jest.fn().mockReturnThis(),
      send: jest.fn().mockReturnThis(),
      sendFile: jest.fn().mockReturnThis(),
      sendStatus: jest.fn().mockReturnThis(),
      set: jest.fn().mockReturnThis(),
      type: jest.fn().mockReturnThis(),
      vary: jest.fn().mockReturnThis()
    } as unknown as Response;

    mockNext = jest.fn();

    // Set up default mock implementations
    mockQuery.mockResolvedValue({ rows: [], rowCount: 0 });
    mockCompare.mockResolvedValue(true);
    mockHash.mockResolvedValue('hashedPassword');
    mockGenSalt.mockResolvedValue('salt');
    mockJwtSign.mockReturnValue('mocked-jwt-token');
    mockJwtVerify.mockReturnValue({ 
      userId: 'user123', 
      email: 'test@example.com',
      type: 'access' 
    });

    // Create new instances for each test
    authController = new AuthController();
    mockClient = {
      query: jest.fn().mockResolvedValue({ rows: [], rowCount: 0 }),
      release: jest.fn(),
      connect: jest.fn(),
      copyFrom: jest.fn(),
      copyTo: jest.fn(),
      pauseDrain: jest.fn(),
      resumeDrain: jest.fn(),
      escapeIdentifier: jest.fn().mockImplementation((str) => `"${str}"`),
      escapeLiteral: jest.fn().mockImplementation((str) => `'${str}'`),
      on: jest.fn(),
      addListener: jest.fn(),
      once: jest.fn(),
      removeListener: jest.fn(),
      off: jest.fn(),
      removeAllListeners: jest.fn(),
      setMaxListeners: jest.fn(),
      getMaxListeners: jest.fn(),
      listeners: jest.fn(),
      rawListeners: jest.fn(),
      emit: jest.fn(),
      listenerCount: jest.fn(),
      prependListener: jest.fn(),
      prependOnceListener: jest.fn(),
      eventNames: jest.fn()
    } as unknown as PoolClient;
  });

  describe('register', () => {
    it('should register a new user', async () => {
      // Arrange
      mockReq.body = {
        email: 'test@example.com',
        password: 'password123',
        name: 'Test User'
      };

      // Mock database responses
      mockQuery
        .mockResolvedValueOnce({ rowCount: 0 }) // User doesn't exist
        .mockResolvedValueOnce({ // User created
          rows: [{ 
            id: 'user123', 
            email: 'test@example.com', 
            is_admin: false,
            name: 'Test User',
            password_hash: 'hashedPassword',
            is_verified: false,
            created_at: new Date(),
            updated_at: new Date()
          }],
          rowCount: 1
        });

      // Act
      await authController.register(mockReq, mockRes, mockNext);

      // Assert
      expect(db.query).toHaveBeenCalledTimes(2);
      expect(bcrypt.hash).toHaveBeenCalledWith('password123', 10);
      expect(mockRes.status).toHaveBeenCalledWith(201);
      expect(mockRes.json).toHaveBeenCalledWith(expect.objectContaining({
        message: 'User registered successfully',
        user: expect.objectContaining({
          email: 'test@example.com',
          isAdmin: false
        })
      }));
    });

    it('should return 400 if user already exists', async () => {
      // Arrange
      mockReq.body = {
        email: 'existing@example.com',
        password: 'password123',
        name: 'Existing User'
      };

      // Mock database response - user already exists
      mockQuery.mockResolvedValueOnce({ 
        rowCount: 1,
        rows: [{ 
          id: 'existing-user-123',
          email: 'existing@example.com',
          password_hash: 'hashedPassword',
          name: 'Existing User',
          is_admin: false,
          is_verified: true,
          created_at: new Date(),
          updated_at: new Date()
        }] 
      });

      // Act
      await authController.register(mockReq, mockRes, mockNext);

      // Assert
      expect(db.query).toHaveBeenCalledTimes(1);
      expect(mockRes.status).toHaveBeenCalledWith(400);
      expect(mockRes.json).toHaveBeenCalledWith({
        error: 'User already exists',
        message: 'A user with this email already exists.'
      });
    });
  });

  describe('login', () => {
    it('should login user with valid credentials', async () => {
      // Arrange
      mockReq.body = {
        email: 'test@example.com',
        password: 'password123'
      };

      // Mock database response - user exists
      const mockQuery = db.query as jest.Mock;
      mockQuery.mockResolvedValueOnce({
        rows: [{
          id: 'user123',
          email: 'test@example.com',
          password: 'hashedPassword',
          is_admin: false,
          name: 'Test User',
          created_at: new Date(),
          updated_at: new Date()
        }],
        rowCount: 1
      });

      // Act
      await authController.login(mockReq, mockRes, mockNext);

      // Assert
      expect(db.query).toHaveBeenCalledTimes(1);
      expect(bcrypt.compare).toHaveBeenCalledWith('password123', 'hashedPassword');
      expect(jwt.sign).toHaveBeenCalled();
      expect(mockRes.status).toHaveBeenCalledWith(200);
      expect(mockRes.json).toHaveBeenCalledWith(expect.objectContaining({
        accessToken: 'mocked-jwt-token',
        user: expect.objectContaining({
          email: 'test@example.com',
          isAdmin: false,
          name: 'Test User'
        })
      }));
    });

    it('should return 401 for invalid credentials', async () => {
      // Arrange
      mockReq.body = {
        email: 'test@example.com',
        password: 'wrongpassword'
      };

      // Mock database response - user exists
      const mockQuery = db.query as jest.Mock;
      mockQuery.mockResolvedValueOnce({
        rows: [{
          id: 'user123',
          email: 'test@example.com',
          password: 'hashedPassword',
          is_admin: false,
          name: 'Test User',
          created_at: new Date(),
          updated_at: new Date()
        }],
        rowCount: 1
      });

      // Mock bcrypt.compare to return false for invalid password
      (bcrypt.compare as jest.Mock).mockResolvedValueOnce(false);

      // Act
      await authController.login(mockReq, mockRes, mockNext);

      // Assert
      expect(mockRes.status).toHaveBeenCalledWith(401);
      expect(mockRes.json).toHaveBeenCalledWith({
        error: 'Invalid email or password',
        message: 'The email or password you entered is incorrect. Please try again.'
      });
    });
  });

  // Add more test cases for other auth controller methods
});
