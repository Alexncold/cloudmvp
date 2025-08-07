import { AuthController } from '../../../src/controllers/authController';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { Pool, PoolClient } from 'pg';
import { createMockRequest, createMockResponse, mockDb } from '../../test-utils/testMocks';

// Import types from pg
import { QueryResult, QueryResultRow } from 'pg';

// Create a type for the query function that matches the database service
type QueryFunction = {
  <T extends QueryResultRow = any>(text: string, params?: any[]): Promise<QueryResult<T>>;
} & {
  mockResolvedValueOnce: <T>(value: QueryResult<T>) => QueryFunction;
  mockRejectedValueOnce: (error: any) => QueryFunction;
  mockResolvedValue: <T>(value: QueryResult<T>) => QueryFunction;
  mockReset: () => void;
};

// Create a mock implementation with proper Jest mock functions
const createMockQuery = (): QueryFunction => {
  // Create a base mock function with the correct call signature
  const baseMock = <T extends QueryResultRow = any>(
    text: string, 
    params?: any[]
  ): Promise<QueryResult<T>> => {
    return Promise.resolve({} as QueryResult<T>);
  };
  
  // Cast to any to allow adding Jest mock properties
  const mockFn = baseMock as any;
  
  // Add Jest mock methods with proper typing
  mockFn.mockResolvedValueOnce = <T>(value: QueryResult<T>) => {
    mockFn.mockImplementationOnce(() => Promise.resolve(value));
    return mockFn;
  };
  
  mockFn.mockRejectedValueOnce = (error: any) => {
    mockFn.mockImplementationOnce(() => Promise.reject(error));
    return mockFn;
  };
  
  mockFn.mockResolvedValue = <T>(value: QueryResult<T>) => {
    mockFn.mockImplementation(() => Promise.resolve(value));
    return mockFn;
  };
  
  mockFn.mockReset = () => {
    mockFn.mockClear();
  };
  
  // Initialize with a default implementation
  mockFn.mockImplementation(<T>() => Promise.resolve({} as QueryResult<T>));
  
  return mockFn as unknown as QueryFunction;
};

// Create mock functions with proper types
const mockQuery = createMockQuery();
const mockGetClient = jest.fn<Promise<PoolClient>, []>();
const mockClose = jest.fn<Promise<void>, []>();
const mockConnect = jest.fn<Promise<void>, []>();

// Create a mock database object that matches the Database class interface
const mockDb = {
  query: mockQuery,
  getClient: mockGetClient,
  close: mockClose,
  connect: mockConnect
};

// Mock the database module
jest.mock('../../../src/services/database', () => ({
  db: mockDb
}));

// Import the mocked db after setting up the mock
import { db } from '../../../src/services/database';

// Export mocks for convenience
export { mockQuery, mockGetClient, mockClose, mockConnect, mockDb };

// Create a mock PoolClient
const mockPoolClient: Partial<PoolClient> = {
  query: jest.fn(),
  release: jest.fn()
};

// Set up default mock implementations
beforeEach(() => {
  // Reset all mocks
  jest.clearAllMocks();
  
  // Set up default mock implementations
  mockQuery.mockResolvedValue({ rows: [], rowCount: 0, command: '', oid: 0, fields: [] });
  mockGetClient.mockResolvedValue(mockPoolClient as PoolClient);
  mockClose.mockResolvedValue(undefined);
  mockConnect.mockResolvedValue(undefined);
  
  // Set up mock implementations for PoolClient
  (mockPoolClient.query as jest.Mock).mockResolvedValue({ rows: [], rowCount: 0, command: '', oid: 0, fields: [] });
  (mockPoolClient.release as jest.Mock).mockResolvedValue(undefined);
  
  // Set up other mocks
  (jwt.sign as jest.Mock).mockReturnValue('mocked-jwt-token');
  (bcrypt.hash as jest.Mock).mockResolvedValue('hashed-password');
  (bcrypt.compare as jest.Mock).mockResolvedValue(true);
  
  // Set up email service mock if needed
  if (emailService) {
    (emailService.sendVerificationEmail as jest.Mock)?.mockResolvedValue(undefined);
    (emailService.sendPasswordResetEmail as jest.Mock)?.mockResolvedValue(undefined);
  }
});

afterAll(async () => {
  // Clean up any resources if needed
  jest.restoreAllMocks();
});

// Types for database query results
type QueryResult<T = any> = {
  rows: T[];
  rowCount: number;
  command?: string;
  oid?: number;
  fields?: any[];
};

// Type for the mock database
type MockDb = {
  query: jest.Mock<Promise<QueryResult>, [string, any[]?]>;
  getClient: jest.Mock<Promise<PoolClient>, []>;
  close: jest.Mock<Promise<void>, []>;
  connect: jest.Mock<Promise<void>, []>;
};

// Setup mocks
jest.mock('bcryptjs', () => ({
  hash: jest.fn().mockResolvedValue('hashedPassword'),
  compare: jest.fn().mockResolvedValue(true),
  genSalt: jest.fn().mockResolvedValue('mockSalt')
}));

jest.mock('jsonwebtoken', () => ({
  sign: jest.fn().mockReturnValue('mock-token'),
  verify: jest.fn().mockReturnValue({
    userId: 'test-user-id',
    email: 'test@example.com',
    role: 'user',
    type: 'access'
  }),
  TokenExpiredError: class MockTokenExpiredError extends Error {
    constructor() {
      super('Token expired');
      this.name = 'TokenExpiredError';
    }
  },
  JsonWebTokenError: class MockJsonWebTokenError extends Error {
    constructor() {
      super('Invalid token');
      this.name = 'JsonWebTokenError';
    }
  }
}));

jest.mock('uuid', () => ({
  v4: () => 'mock-uuid'
}));

// Mock crypto module with proper TypeScript types
const mockRandomBytes = jest.fn().mockReturnValue({ toString: () => 'mock-token' });

jest.mock('crypto', () => ({
  randomBytes: mockRandomBytes
}));

// Use manual mocks for database and email service
jest.mock('../../../src/services/emailService', () => ({
  sendVerificationEmail: jest.fn().mockResolvedValue(undefined),
  sendPasswordResetEmail: jest.fn().mockResolvedValue(undefined)
}));

// Import the mocked modules
const emailService = require('../../../src/services/emailService');

// Helper types for request and response mocks
interface MockRequest extends Partial<Request> {
  body?: any;
  params?: Record<string, string>;
  query?: Record<string, string | string[]>;
  headers?: Record<string, string>;
  cookies?: Record<string, string>;
  user?: any;
}

type MockResponse = {
  status: jest.Mock<any, [number]>;
  json: jest.Mock<any, [any]>;
  send: jest.Mock<any, [any?]>;
  sendStatus: jest.Mock<any, [number]>;
  redirect: jest.Mock<any, [string | number, string?]>;
  cookie: jest.Mock<any, [string, string, any?]>;
  clearCookie: jest.Mock<any, [string, any?]>;
  locals: Record<string, any>;
  [key: string]: any; // For any other properties that might be accessed
};

// Helper function to create a mock request
const mockRequest = (overrides: MockRequest = {}): MockRequest => {
  const req: MockRequest = {
    body: {},
    params: {},
    query: {},
    headers: {},
    cookies: {},
    ...overrides,
  };
  return req;
};

// Helper function to create a mock response
const mockResponse = (): MockResponse => {
  const res: MockResponse = {
    status: jest.fn(),
    json: jest.fn(),
    send: jest.fn(),
    sendStatus: jest.fn(),
    redirect: jest.fn(),
    cookie: jest.fn(),
    clearCookie: jest.fn(),
    locals: {}
  };

  // Chain the methods
  res.status.mockReturnValue(res);
  res.json.mockReturnValue(res);
  res.send.mockReturnValue(res);
  res.sendStatus.mockReturnValue(res);
  res.redirect.mockReturnValue(res);
  res.cookie.mockReturnValue(res);
  res.clearCookie.mockReturnValue(res);

  return res;
};

describe('Auth Controller', () => {
  let authController: AuthController;
  let req: Partial<Request>;
  let res: MockResponse;
  let mockClient: any;

  beforeAll(() => {
    // Setup default mock implementations
    (bcrypt.hash as jest.Mock).mockResolvedValue('hashedPassword');
    (bcrypt.compare as jest.Mock).mockResolvedValue(true);
    (bcrypt.genSalt as jest.Mock).mockResolvedValue('mockSalt');
    (jwt.sign as jest.Mock).mockReturnValue('mockToken');
    (jwt.verify as jest.Mock).mockReturnValue({
      userId: 'test-user-id',
      email: 'test@example.com',
      role: 'user',
      type: 'access'
    });
  });

  beforeEach(() => {
    // Create fresh instances for each test
    authController = new AuthController();
    req = mockRequest();
    res = mockResponse();
    
    // Reset all mocks
    jest.clearAllMocks();
    
    // Setup default mock client
    mockClient = {
      query: jest.fn(),
      release: jest.fn()
    };
    
    // Setup default database mock implementations
    mockQuery.mockReset();
    mockGetClient.mockResolvedValue(mockClient as PoolClient);
    mockClose.mockReset();
    mockConnect.mockReset();
    
    // Set up default mock responses
    mockQuery.mockResolvedValue({ rows: [], rowCount: 0, command: '', oid: 0, fields: [] });
    mockGetClient.mockResolvedValue(mockClient as PoolClient);
    
    // Reset other mocks
    (jwt.sign as jest.Mock).mockReturnValue('mocked-jwt-token');
    (bcrypt.hash as jest.Mock).mockResolvedValue('hashed-password');
    (bcrypt.compare as jest.Mock).mockResolvedValue(true);
    
    // Reset email service mocks
    if (emailService) {
      (emailService.sendVerificationEmail as jest.Mock)?.mockResolvedValue(undefined);
      (emailService.sendPasswordResetEmail as jest.Mock)?.mockResolvedValue(undefined);
    }
  });

  afterEach(() => {
    // Clean up after each test
    jest.clearAllMocks();
  });
  
  afterAll(async () => {
    // Restore all mocks
    jest.restoreAllMocks();
  });

  describe('register', () => {
    it('should register a new user successfully', async () => {
      // Arrange
      const testReq = {
        body: {
          email: 'test@example.com',
          password: 'password123',
          name: 'Test User'
        }
      };
      
      const testRes = mockResponse();
      const next = jest.fn();

      // Mock database responses
      mockQuery
        .mockResolvedValueOnce({ 
          rowCount: 0,
          rows: [],
          command: '',
          oid: 0,
          fields: []
        }) // User doesn't exist
        .mockResolvedValueOnce({ 
          rowCount: 1,
          rows: [{
            id: 'user123',
            email: 'test@example.com',
            name: 'Test User',
            password_hash: 'hashedPassword',
            is_verified: false,
            verification_token: 'mock-verification-token',
            verification_token_expires: new Date(Date.now() + 24 * 60 * 60 * 1000), // 1 day from now
            created_at: new Date(),
            updated_at: new Date()
          }],
          command: 'INSERT',
          oid: 0,
          fields: []
        }); // User created
        
      // Configure JWT sign mock for tokens
      (jwt.sign as jest.Mock).mockImplementation(() => 'mock-token');
      (bcrypt.hash as jest.Mock).mockResolvedValue('hashedPassword');

      // Act
      await authController.register(testReq as Request, testRes as unknown as Response, next);

      // Assert
      expect(testRes.status).toHaveBeenCalledWith(201);
      
      const responseArg = testRes.json.mock.calls[0][0];
      expect(responseArg).toHaveProperty('accessToken', 'mock-token');
      expect(responseArg).toHaveProperty('refreshToken', 'mock-token');
      expect(responseArg).toHaveProperty('expiresIn', expect.any(Number));
      expect(responseArg).toHaveProperty('message', 'Registration successful. Please check your email to verify your account.');
      expect(responseArg).toHaveProperty('user');
      expect(responseArg.user).toHaveProperty('email', 'test@example.com');
      expect(responseArg.user).toHaveProperty('is_verified', false);
      
      // Verify bcrypt was called with the password
      expect(bcrypt.genSalt).toHaveBeenCalledWith(10);
      expect(bcrypt.hash).toHaveBeenCalledWith('password123', 'mockSalt');
      
      // Verify JWT sign was called
      expect(jwt.sign).toHaveBeenCalledWith(
        { userId: expect.any(String), email: 'test@example.com' },
        expect.any(String),
        { expiresIn: '15m' }
      );
      
      // Verify email was sent
      expect(emailService.sendVerificationEmail).toHaveBeenCalledWith(
        'test@example.com',
        expect.any(String) // verification token
      );
    });

    it('should return 400 if user already exists', async () => {
      // Arrange
      req.body = {
        email: 'existing@example.com',
        password: 'password123',
        name: 'Existing User'
      };

      // Mock database response - user already exists
      db.query.mockResolvedValueOnce({
        rowCount: 1,
        rows: [{
          id: 'existing-user-123',
          email: 'existing@example.com',
          name: 'Existing User',
          password_hash: 'existing-hash',
          is_verified: true,
          created_at: new Date(),
          updated_at: new Date()
        }]
      });

      // Act
      await authController.register(req as Request, res as unknown as Response, jest.fn());

      // Assert
      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith({
        success: false,
        message: 'User already exists with this email'
      });
    });

    it('should return 500 if database error occurs', async () => {
      // Arrange
      req.body = {
        email: 'test@example.com',
        password: 'password123',
        name: 'Test User'
      };

      // Mock database to throw an error
      db.query.mockRejectedValueOnce(new Error('Database error'));

      // Act
      await authController.register(req as Request, res as unknown as Response, jest.fn());

      // Assert
      expect(res.status).toHaveBeenCalledWith(500);
      expect(res.json).toHaveBeenCalledWith({
        success: false,
        message: 'Error registering user',
        error: expect.any(Error)
      });
    });
  });

  describe('login', () => {
    it('should login user with valid credentials', async () => {
      // Arrange
      const req = {
        body: {
          email: 'test@example.com',
          password: 'password123'
        }
      } as Request;
      
      const res = mockResponse();
      const next = jest.fn();

      // Mock database response - user exists with hashed password
      mockQuery.mockResolvedValueOnce({
        rowCount: 1,
        rows: [{
          id: 'user123',
          email: 'test@example.com',
          name: 'Test User',
          password_hash: 'hashedPassword',
          is_verified: true,
          created_at: new Date(),
          updated_at: new Date()
        }],
        command: 'SELECT',
        oid: 0,
        fields: []
      });

      // Configure bcrypt to return true for password comparison
      (bcrypt.compare as jest.Mock).mockResolvedValue(true);

      // Configure JWT sign mock for tokens
      (jwt.sign as jest.Mock).mockImplementation((payload, secret, options) => {
        if (options?.expiresIn === '15m') return 'mock-access-token';
        if (options?.expiresIn === '7d') return 'mock-refresh-token';
        return 'mock-token';
      });

      // Act
      await authController.login(req as Request, res as unknown as Response, next);

      // Assert
      expect(res.status).toHaveBeenCalledWith(200);

      const responseArg = res.json.mock.calls[0][0];
      expect(responseArg).toHaveProperty('accessToken', 'mock-access-token');
      expect(responseArg).toHaveProperty('refreshToken', 'mock-refresh-token');
      expect(responseArg).toHaveProperty('expiresIn', 900); // 15 minutes in seconds
      expect(responseArg).toHaveProperty('user');
      expect(responseArg.user).toEqual({
        id: 'user123',
        email: 'test@example.com',
        name: 'Test User',
        is_verified: true
      });

      // Verify bcrypt was called with the correct password
      expect(bcrypt.compare).toHaveBeenCalledWith('password123', 'hashedPassword');

      // Verify JWT sign was called with correct parameters
      expect(jwt.sign).toHaveBeenCalledWith(
        { userId: expect.any(String), email: 'test@example.com' },
        expect.any(String),
        { expiresIn: '15m' }
      );
      
      // Verify email was sent
      expect(emailService.sendVerificationEmail).toHaveBeenCalledWith(
        'test@example.com',
        expect.any(String) // verification token
      );
    });

    it('should return 400 if user already exists', async () => {
      // Arrange
      const testReq = {
        body: {
          email: 'existing@example.com',
          password: 'password123',
          name: 'Existing User'
        }
      } as Request;
      
      const testRes = mockResponse();
      const next = jest.fn();

      // Mock database response - user already exists
      mockQuery.mockResolvedValueOnce({
        rowCount: 1,
        rows: [{
          id: 'existing-user-123',
          email: 'existing@example.com',
          name: 'Existing User',
          password_hash: 'existing-hash',
          is_verified: true,
          created_at: new Date(),
          updated_at: new Date()
        }],
        command: 'SELECT',
        oid: 0,
        fields: []
      });

      // Act
      await authController.login(testReq as Request, testRes as unknown as Response, next);

      // Assert
      expect(res.status).toHaveBeenCalledWith(200);
      
      // Get the response argument from the first call to res.json
      const responseArg = res.json.mock.calls[0][0];
      
      // Verify the response structure
      expect(responseArg).toHaveProperty('user');
      expect(responseArg.user).toHaveProperty('id', 'user123');
      expect(responseArg.user).toHaveProperty('email', 'test@example.com');
      expect(responseArg.user).toHaveProperty('name', 'Test User');
      expect(responseArg.user).toHaveProperty('is_verified', true);
      
      // Verify tokens are present in the response
      expect(responseArg).toHaveProperty('accessToken');
      expect(responseArg).toHaveProperty('refreshToken');
      expect(responseArg).toHaveProperty('expiresIn', expect.any(Number));
      expect(responseArg).toHaveProperty('message', 'Login successful');
      
      // Verify password comparison was called with correct arguments
      expect(bcrypt.compare).toHaveBeenCalledWith('password123', 'hashedPassword');
      
      // Verify database was updated with refresh token
      expect(db.query).toHaveBeenCalledWith(
        'UPDATE users SET refresh_token_hash = $1, updated_at = NOW() WHERE id = $2',
        [expect.any(String), 'user123']
      );
      
      // Verify JWT sign was called for access token
      expect(jwt.sign).toHaveBeenCalledWith(
        { 
          userId: 'user123', 
          email: 'test@example.com',
          role: 'user',
          type: 'access'
        },
        expect.any(String),
        { expiresIn: '15m' }
      );
      
      // Verify JWT sign was called for refresh token
      expect(jwt.sign).toHaveBeenCalledWith(
        { 
          userId: 'user123', 
          email: 'test@example.com',
          type: 'refresh'
        },
        expect.any(String),
        { expiresIn: '7d' }
      );
      
      // Verify cookies were set
      expect(res.cookie).toHaveBeenCalledWith(
        'access_token',
        expect.any(String),
        expect.objectContaining({
          httpOnly: true,
          secure: process.env.NODE_ENV === 'production',
          sameSite: 'strict',
          maxAge: 900000 // 15 minutes in ms
        })
      );
      
      expect(res.cookie).toHaveBeenCalledWith(
        'refresh_token',
        expect.any(String),
        expect.objectContaining({
          httpOnly: true,
          secure: process.env.NODE_ENV === 'production',
          sameSite: 'strict',
          maxAge: 604800000 // 7 days in ms
        })
      );
      
      expect(res.cookie).toHaveBeenCalledWith(
        'authenticated',
        'true',
        expect.objectContaining({
          secure: process.env.NODE_ENV === 'production',
          sameSite: 'strict',
          maxAge: 604800000 // 7 days in ms
        })
      );
    });

    it('should return 401 for invalid credentials', async () => {
      // Arrange
      req.body = {
        email: 'test@example.com',
        password: 'wrongpassword'
      };

      // Mock database response - user exists
      db.query.mockResolvedValue({
        rowCount: 1,
        rows: [{
          id: 'user123',
          email: 'test@example.com',
          name: 'Test User',
          password_hash: 'hashedPassword',
          is_verified: true,
          created_at: new Date(),
          updated_at: new Date()
        }]
      });

      // Mock bcrypt to return false for password comparison
      (bcrypt.compare as jest.Mock).mockResolvedValue(false);
      
      // Reset any previous JWT sign calls
      (jwt.sign as jest.Mock).mockClear();

      // Act
      const next = jest.fn();
      await authController.login(req as Request, res as unknown as Response, next);

      // Assert
      expect(res.status).toHaveBeenCalledWith(401);
      expect(res.json).toHaveBeenCalledWith({
        success: false,
        error: 'The email or password you entered is incorrect. Please try again.'
      });
      
      // Verify no tokens were generated
      expect(jwt.sign).not.toHaveBeenCalled();
    });
  });

  // Add more test cases for other controller methods...
});
