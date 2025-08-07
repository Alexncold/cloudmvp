import { AuthController } from '../../../src/controllers/authController';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';
import { mockDb } from '../../test-utils/testMocks';
import { createMockRequest, createMockResponse } from '../../test-utils/testMocks';

// Mock the database module
jest.mock('../../../src/services/database');

// Mock bcrypt
jest.mock('bcryptjs');

// Mock jsonwebtoken
jest.mock('jsonwebtoken');

// Mock uuid
jest.mock('uuid', () => ({
  v4: jest.fn().mockReturnValue('mocked-uuid')
}));

describe('AuthController', () => {
  let authController: AuthController;
  let testReq: any;
  let testRes: any;
  let next: jest.Mock;

  beforeEach(() => {
    // Reset all mocks before each test
    jest.clearAllMocks();
    
    // Create a fresh instance of the controller for each test
    authController = new AuthController();
    
    // Setup default request and response objects
    testReq = createMockRequest();
    testRes = createMockResponse();
    next = jest.fn();

    // Set up default mock implementations
    (bcrypt.hash as jest.Mock).mockResolvedValue('hashedPassword');
    (bcrypt.compare as jest.Mock).mockResolvedValue(true);
    (jwt.sign as jest.Mock).mockReturnValue('mockToken');
    (jwt.verify as jest.Mock).mockReturnValue({ userId: 'test-user-id' });
  });

  describe('register', () => {
    it('should register a new user successfully', async () => {
      // Mock database response for checking if user exists
      mockDb.query.mockResolvedValueOnce({ rows: [], rowCount: 0 });
      
      // Mock database response for inserting new user
      mockDb.query.mockResolvedValueOnce({ 
        rows: [{ 
          id: 'test-user-id', 
          email: 'test@example.com',
          name: 'Test User',
          is_admin: false
        }], 
        rowCount: 1 
      });

      // Set up request body
      testReq.body = {
        email: 'test@example.com',
        password: 'password123',
        name: 'Test User'
      };

      await authController.register(testReq, testRes, next);

      // Verify response
      expect(testRes.status).toHaveBeenCalledWith(201);
      expect(testRes.json).toHaveBeenCalledWith(
        expect.objectContaining({
          message: 'User registered successfully',
          user: expect.objectContaining({
            email: 'test@example.com',
            name: 'Test User'
          })
        })
      );
    });

    it('should return 400 if user already exists', async () => {
      // Mock database response for checking if user exists
      mockDb.query.mockResolvedValueOnce({ 
        rows: [{ id: 'existing-user-id' }], 
        rowCount: 1 
      });

      // Set up request body
      testReq.body = {
        email: 'existing@example.com',
        password: 'password123',
        name: 'Existing User'
      };

      await authController.register(testReq, testRes, next);

      // Verify response
      expect(testRes.status).toHaveBeenCalledWith(400);
      expect(testRes.json).toHaveBeenCalledWith(
        expect.objectContaining({
          error: 'User already exists'
        })
      );
    });
  });

  describe('login', () => {
    it('should login user with valid credentials', async () => {
      const hashedPassword = await bcrypt.hash('password123', 10);
      const mockUser = {
        id: 'test-user-id',
        email: 'test@example.com',
        password: hashedPassword,
        name: 'Test User',
        is_admin: false
      };

      // Mock database response for finding user
      mockDb.query.mockResolvedValueOnce({ 
        rows: [mockUser], 
        rowCount: 1 
      });

      // Set up request body
      testReq.body = {
        email: 'test@example.com',
        password: 'password123'
      };

      await authController.login(testReq, testRes, next);

      // Verify response
      expect(testRes.status).toHaveBeenCalledWith(200);
      expect(testRes.json).toHaveBeenCalledWith(
        expect.objectContaining({
          message: 'Login successful',
          token: expect.any(String),
          user: expect.objectContaining({
            id: 'test-user-id',
            email: 'test@example.com',
            name: 'Test User'
          })
        })
      );
    });
  });

  describe('refreshToken', () => {
    it('should refresh token with valid refresh token', async () => {
      const mockRefreshToken = {
        id: 'refresh-token-id',
        user_id: 'test-user-id',
        token: 'valid-refresh-token',
        expires_at: new Date(Date.now() + 86400000), // 1 day from now
        created_at: new Date()
      };

      const mockUser = {
        id: 'test-user-id',
        email: 'test@example.com',
        name: 'Test User',
        is_admin: false
      };

      // Mock database responses
      mockDb.query.mockResolvedValueOnce({ 
        rows: [mockRefreshToken], 
        rowCount: 1 
      });
      
      mockDb.query.mockResolvedValueOnce({ 
        rows: [mockUser], 
        rowCount: 1 
      });

      // Set up request body
      testReq.body = {
        refreshToken: 'valid-refresh-token'
      };

      await authController.refreshToken(testReq, testRes, next);

      // Verify response
      expect(testRes.status).toHaveBeenCalledWith(200);
      expect(testRes.json).toHaveBeenCalledWith(
        expect.objectContaining({
          token: expect.any(String),
          refreshToken: expect.any(String)
        })
      );
    });
  });
});
