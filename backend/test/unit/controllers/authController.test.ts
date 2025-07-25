import { Request, Response } from 'express';
import { IncomingHttpHeaders } from 'http';
import { createAuthController } from '../../../src/controllers/authController';
import { DatabaseService } from '../../../src/services/db';

// Mock the DatabaseService
jest.mock('../../../src/services/db');

// Create a mock DatabaseService
const mockDbService = new DatabaseService();
const { 
  register, 
  login, 
  verifyEmail,
  refreshToken,
  logout,
  getCurrentUser
} = createAuthController(mockDbService);

// Create a custom mock response type that matches our implementation
type MockResponse = Response & {
  status: jest.Mock<MockResponse, [number]>;
  json: jest.Mock<MockResponse, [any]>;
  send: jest.Mock<MockResponse, [any?]>;
  sendStatus: jest.Mock<MockResponse, [number]>;
  redirect: jest.Mock<MockResponse, [string]> & ((status: number, url: string) => void);
  cookie: jest.Mock<MockResponse, [string, string, any?]>;
  clearCookie: jest.Mock<MockResponse, [string, any?]>;
  locals: Record<string, any>;
  [key: string]: any;
};

// Mock request and response helpers
const mockRequest = (overrides: Partial<Request> = {}): Partial<Request> => ({
  body: {},
  params: {},
  query: {},
  headers: {} as IncomingHttpHeaders,
  ...overrides,
});

const mockResponse = () => {
  const res: any = {};
  res.status = jest.fn().mockImplementation((status) => {
    console.log(`Response status set to: ${status}`);
    res.statusCode = status;
    return res;
  });
  res.json = jest.fn().mockImplementation((body) => {
    console.log('Response body:', JSON.stringify(body, null, 2));
    return res;
  });
  res.send = jest.fn().mockReturnValue(res);
  res.sendStatus = jest.fn().mockReturnValue(res);
  res.redirect = jest.fn().mockImplementation(((url: string) => res) as any);
  res.cookie = jest.fn().mockReturnValue(res);
  res.clearCookie = jest.fn().mockReturnValue(res);
  res.locals = {};
  return res;
};

// Mock JWT and bcrypt
jest.mock('jsonwebtoken', () => ({
  sign: jest.fn().mockReturnValue('mockToken'),
  verify: jest.fn().mockImplementation(() => ({
    userId: 'user123',
    email: 'test@example.com',
    type: 'access'
  }))
}));

jest.mock('bcryptjs', () => ({
  hash: jest.fn().mockResolvedValue('hashedPassword'),
  compare: jest.fn().mockResolvedValue(true)
}));

describe('Auth Controller', () => {
  let req: Partial<Request>;
  let res: MockResponse;
  let mockClient: any;

  beforeEach(() => {
    // Reset mocks before each test
    jest.clearAllMocks();
    
    // Setup default request and response objects
    req = mockRequest();
    res = mockResponse();
    
    // Setup default database mock client
    mockClient = {
      query: jest.fn().mockResolvedValue({ 
        rows: [], 
        rowCount: 0,
        command: '',
        oid: 0,
        fields: []
      }),
      release: jest.fn()
    };
    
    (mockDbService.getClient as jest.Mock).mockResolvedValue(mockClient);
  });

  describe('register', () => {
    it('should register a new user successfully', async () => {
      // Mock request body
      req.body = {
        email: 'test@example.com',
        password: 'password123',
        name: 'Test User'
      };

      // Mock database responses
      const mockUser = {
        id: 'user123',
        email: 'test@example.com',
        name: 'Test User',
        password_hash: 'hashedpassword',
        is_verified: false,
        created_at: new Date(),
        updated_at: new Date(),
        google_id: null,
        google_refresh_token: null,
        verification_token: 'verification-token',
        verification_token_expires: new Date(Date.now() + 24 * 60 * 60 * 1000), // 1 day from now
        password_reset_token: null,
        password_reset_expires: null,
        refresh_token: null
      };
      
      // Mock the database queries for user existence check and user creation
      mockClient.query
        .mockResolvedValueOnce({ rows: [], rowCount: 0 }) // User doesn't exist
        .mockResolvedValueOnce({ 
          rows: [mockUser], 
          rowCount: 1 
        }) // User created
        .mockResolvedValue({ rows: [], rowCount: 0 }); // Any subsequent queries

      // Call the register function
      await register(req as Request, res as unknown as Response);

      // Assertions
      expect(res.status).toHaveBeenCalledWith(201);
      
      // Get the actual response that was sent
      const responseArg = res.json.mock.calls[0][0];
      
      // Check the structure of the response
      expect(responseArg).toHaveProperty('accessToken');
      expect(responseArg).toHaveProperty('user');
      
      // Check the user object structure
      const user = responseArg.user;
      expect(user).toHaveProperty('id', 'user123');
      expect(user).toHaveProperty('email', 'test@example.com');
      expect(user).toHaveProperty('is_verified', false);
      expect(user).toHaveProperty('created_at');
      expect(user).toHaveProperty('updated_at');
      
      // The name might be in a name field or split into first_name/last_name
      if ('name' in user) {
        expect(user.name).toBe('Test User');
      }
      expect(res.cookie).toHaveBeenCalledWith(
        'refreshToken',
        expect.any(String),
        expect.objectContaining({
          httpOnly: true,
          secure: process.env.NODE_ENV === 'production',
          sameSite: 'strict',
          maxAge: expect.any(Number)
        })
      );
    });

    it('should return 400 if user already exists', async () => {
      // Mock request body
      req.body = {
        email: 'existing@example.com',
        password: 'password123',
        name: 'Existing User'
      };

      // Mock database response for existing user
      mockClient.query.mockResolvedValueOnce({ 
        rows: [{ id: 'existing123' }], 
        rowCount: 1 
      });

      // Call the register function
      await register(req as Request, res as unknown as Response);

      // Assertions
      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith({
        error: 'User already exists'
      });
    });
  });

  describe('login', () => {
    let bcrypt: any;
    let jwt: any;
    let mockClient: any;

    beforeEach(() => {
      // Reset mocks before each test
      jest.clearAllMocks();
      
      // Setup default request and response objects
      req = mockRequest();
      res = mockResponse();
      
      // Get fresh mocks for each test
      bcrypt = require('bcryptjs');
      jwt = require('jsonwebtoken');
      
      // Setup mock client for database operations
      mockClient = {
        query: jest.fn(),
        release: jest.fn().mockImplementation(() => Promise.resolve())
      };
      
      // Mock the database service to return our mock client
      (mockDbService.getClient as jest.Mock).mockImplementation(() => {
        console.log('getClient called, returning mock client');
        return Promise.resolve(mockClient);
      });

      // Mock the validationResult function
      jest.mock('express-validator', () => ({
        ...jest.requireActual('express-validator'),
        validationResult: jest.fn().mockReturnValue({
          isEmpty: () => true,
          array: () => [],
          formatWith: jest.fn().mockReturnThis(),
          throw: jest.fn()
        })
      }));
    });

    it('should login a user with valid credentials', async () => {
      // Mock request body
      req.body = {
        email: 'test@example.com',
        password: 'password123'
      };

      // Mock database response for finding user
      const mockUser = {
        id: 'user123',
        email: 'test@example.com',
        name: 'Test User',
        password_hash: 'hashedpassword',
        is_verified: true,
        created_at: new Date(),
        updated_at: new Date(),
        google_id: null,
        google_refresh_token: null,
        verification_token: null,
        verification_token_expires: null,
        password_reset_token: null,
        password_reset_expires: null,
        refresh_token: null
      };

      // Mock the database queries for the login flow
      mockClient.query
        // First query: Find user by email
        .mockResolvedValueOnce({ 
          rows: [mockUser], 
          rowCount: 1 
        })
        // Second query: Update refresh token
        .mockResolvedValueOnce({ rowCount: 1 });

      // Mock bcrypt.compare to return true (valid password)
      bcrypt.compare.mockResolvedValueOnce(true);
      
      // Mock JWT sign to return tokens
      jwt.sign.mockImplementation((payload: any) => {
        return payload.type === 'access' ? 'mock-access-token' : 'mock-refresh-token';
      });

      // Call the login function
      await login(req as Request, res as unknown as Response);
      
      // Verify the response status was called with 200
      expect(res.status).toHaveBeenCalledWith(200);
      
      // Verify the response structure
      expect(res.json).toHaveBeenCalledWith(expect.objectContaining({
        user: expect.objectContaining({
          id: 'user123',
          email: 'test@example.com',
          is_verified: true
        }),
        accessToken: 'mock-access-token'
      }));
      
      // Verify bcrypt.compare was called with correct arguments
      expect(bcrypt.compare).toHaveBeenCalledWith('password123', 'hashedpassword');
      
      // Verify the refresh token cookie was set
      expect(res.cookie).toHaveBeenCalledWith(
        'refreshToken', 
        'mock-refresh-token', 
        expect.objectContaining({
          httpOnly: true,
          secure: false, // NODE_ENV is 'test'
          sameSite: 'strict',
          maxAge: 30 * 24 * 60 * 60 * 1000 // 30 days in milliseconds
        })
      );
    });

    it('should return 401 for invalid credentials', async () => {
      // Mock request body
      req.body = {
        email: 'test@example.com',
        password: 'wrongpassword'
      };

      // Mock database response for finding user
      const mockUser = {
        id: 'user123',
        email: 'test@example.com',
        name: 'Test User',
        password_hash: 'hashedpassword',
        is_verified: true,
        created_at: new Date(),
        updated_at: new Date(),
        google_id: null,
        google_refresh_token: null,
        verification_token: null,
        verification_token_expires: null,
        password_reset_token: null,
        password_reset_expires: null,
        refresh_token: null
      };
      
      // Mock database query to return user
      mockClient.query.mockResolvedValueOnce({ 
        rows: [mockUser], 
        rowCount: 1 
      });

      // Mock bcrypt compare to return false (invalid password)
      bcrypt.compare.mockResolvedValueOnce(false);

      // Call the login function
      await login(req as Request, res as unknown as Response);

      // Assertions for invalid credentials
      expect(res.status).toHaveBeenCalledWith(401);
      expect(res.json).toHaveBeenCalledWith({
        error: 'Invalid email or password'
      });
    });
  });

  // Add more test suites for other controller methods (verifyEmail, refreshToken, etc.)
  // ...
});
