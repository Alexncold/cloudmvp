import { Request, Response } from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { authController } from '../../../src/controllers/authController';
import { DatabaseService } from '../../../src/services/databaseService';
import { EmailService } from '../../../src/services/emailService';

// Mock dependencies
jest.mock('bcryptjs');
jest.mock('jsonwebtoken');
jest.mock('../../../src/services/databaseService');
jest.mock('../../../src/services/emailService');

// Mock database service
const mockQuery = jest.fn();
const mockRelease = jest.fn();
const mockClient = {
  query: mockQuery,
  release: mockRelease,
};
(DatabaseService.getInstance as jest.Mock).mockImplementation(() => ({
  getClient: jest.fn().mockResolvedValue(mockClient),
}));

// Mock email service
const mockSendVerificationEmail = jest.fn();
(EmailService as jest.Mock).mockImplementation(() => ({
  sendVerificationEmail: mockSendVerificationEmail,
}));

// Mock response object
const mockResponse = () => {
  const res: Partial<Response> = {};
  res.status = jest.fn().mockReturnThis();
  res.json = jest.fn().mockReturnThis();
  res.cookie = jest.fn().mockReturnThis();
  return res;
};

// Mock request object
const mockRequest = (body = {}, params = {}, query = {}) => ({
  body,
  params,
  query,
  cookies: {},
  header: jest.fn(),
});

describe('Auth Controller', () => {
  let testRes: ReturnType<typeof mockResponse>;
  let next: jest.Mock;

  beforeEach(() => {
    // Reset all mocks before each test
    jest.clearAllMocks();
    
    // Setup fresh response and next function for each test
    testRes = mockResponse();
    next = jest.fn();
    
    // Default mock implementations
    (bcrypt.genSalt as jest.Mock).mockResolvedValue('mockSalt');
    (bcrypt.hash as jest.Mock).mockResolvedValue('hashedPassword');
    (bcrypt.compare as jest.Mock).mockResolvedValue(true);
    (jwt.sign as jest.Mock)
      .mockReturnValueOnce('mock-access-token') // access token
      .mockReturnValueOnce('mock-refresh-token'); // refresh token
  });

  afterAll(async () => {
    // Clean up after all tests
    jest.restoreAllMocks();
  });

  describe('register', () => {
    it('should register a new user successfully', async () => {
      // Arrange
      const testReq = mockRequest({
        name: 'Test User',
        email: 'test@example.com',
        password: 'password123'
      });

      // Mock database response - no existing user
      mockQuery.mockResolvedValueOnce({ rowCount: 0, rows: [] });
      
      // Mock database response - successful insert
      mockQuery.mockResolvedValueOnce({
        rowCount: 1,
        rows: [{
          id: 'user123',
          email: 'test@example.com',
          name: 'Test User',
          is_verified: false,
          created_at: new Date(),
          updated_at: new Date()
        }]
      });

      // Act
      await authController.register(testReq as Request, testRes as unknown as Response, next);

      // Assert
      expect(testRes.status).toHaveBeenCalledWith(201);
      
      const responseArg = testRes.json.mock.calls[0][0];
      expect(responseArg).toHaveProperty('message', 'Registration successful. Please check your email to verify your account.');
      expect(responseArg).toHaveProperty('user');      
      expect(responseArg.user).toHaveProperty('email', 'test@example.com');
      expect(responseArg.user).toHaveProperty('is_verified', false);
      
      // Verify bcrypt was called with the password
      expect(bcrypt.genSalt).toHaveBeenCalledWith(10);
      expect(bcrypt.hash).toHaveBeenCalledWith('password123', 'mockSalt');
      
      // Verify email was sent
      expect(mockSendVerificationEmail).toHaveBeenCalled();
    });

    it('should return 400 if email already exists', async () => {
      // Arrange
      const testReq = mockRequest({
        name: 'Test User',
        email: 'existing@example.com',
        password: 'password123'
      });

      // Mock database response - user already exists
      mockQuery.mockResolvedValue({ 
        rowCount: 1, 
        rows: [{ email: 'existing@example.com' }] 
      });

      // Act
      await authController.register(testReq as Request, testRes as unknown as Response, next);

      // Assert
      expect(testRes.status).toHaveBeenCalledWith(400);
      expect(testRes.json).toHaveBeenCalledWith({
        success: false,
        error: 'Email already in use'
      });
    });
  });

  describe('login', () => {
    it('should login user with valid credentials', async () => {
      // Arrange
      const testReq = mockRequest({
        email: 'test@example.com',
        password: 'password123'
      });

      // Mock database response - user exists and is verified
      mockQuery.mockResolvedValue({
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

      // Act
      await authController.login(testReq as Request, testRes as unknown as Response, next);

      // Assert
      expect(testRes.status).toHaveBeenCalledWith(200);
      
      const responseArg = testRes.json.mock.calls[0][0];
      expect(responseArg).toHaveProperty('accessToken', 'mock-access-token');
      expect(responseArg).toHaveProperty('refreshToken', 'mock-refresh-token');
      expect(responseArg).toHaveProperty('user');
      expect(responseArg.user).toHaveProperty('email', 'test@example.com');
      
      // Verify bcrypt was called with the correct password
      expect(bcrypt.compare).toHaveBeenCalledWith('password123', 'hashedPassword');
      
      // Verify JWT sign was called with correct parameters
      expect(jwt.sign).toHaveBeenCalledWith(
        { userId: 'user123', email: 'test@example.com' },
        process.env.JWT_SECRET || 'your-secret-key',
        { expiresIn: '15m' }
      );
    });

    it('should return 400 if email is missing', async () => {
      // Arrange
      const testReq = mockRequest({ password: 'password123' });

      // Act
      await authController.login(testReq as Request, testRes as unknown as Response, next);

      // Assert
      expect(testRes.status).toHaveBeenCalledWith(400);
      expect(testRes.json).toHaveBeenCalledWith({
        success: false,
        error: 'Email and password are required'
      });
    });

    it('should return 400 if password is missing', async () => {
      // Arrange
      const testReq = mockRequest({ email: 'test@example.com' });

      // Act
      await authController.login(testReq as Request, testRes as unknown as Response, next);

      // Assert
      expect(testRes.status).toHaveBeenCalledWith(400);
      expect(testRes.json).toHaveBeenCalledWith({
        success: false,
        error: 'Email and password are required'
      });
    });

    it('should return 401 if user is not found', async () => {
      // Arrange
      const testReq = mockRequest({
        email: 'nonexistent@example.com',
        password: 'password123'
      });

      // Mock database response - user not found
      mockQuery.mockResolvedValue({ 
        rowCount: 0, 
        rows: [],
        command: 'SELECT',
        oid: 0,
        fields: []
      });

      // Act
      await authController.login(testReq as Request, testRes as unknown as Response, next);

      // Assert
      expect(testRes.status).toHaveBeenCalledWith(401);
      expect(testRes.json).toHaveBeenCalledWith({
        success: false,
        error: 'Invalid credentials'
      });
    });

    it('should return 401 if password is incorrect', async () => {
      // Arrange
      const testReq = mockRequest({
        email: 'test@example.com',
        password: 'wrongpassword'
      });

      // Mock database response - user exists
      mockQuery.mockResolvedValue({
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

      // Mock bcrypt to return false for password comparison
      (bcrypt.compare as jest.Mock).mockResolvedValue(false);

      // Act
      await authController.login(testReq as Request, testRes as unknown as Response, next);

      // Assert
      expect(testRes.status).toHaveBeenCalledWith(401);
      expect(testRes.json).toHaveBeenCalledWith({
        success: false,
        error: 'Invalid credentials'
      });
    });

    it('should return 403 if user is not verified', async () => {
      // Arrange
      const testReq = mockRequest({
        email: 'unverified@example.com',
        password: 'password123'
      });

      // Mock database response - user exists but is not verified
      mockQuery.mockResolvedValue({
        rowCount: 1,
        rows: [{
          id: 'user123',
          email: 'unverified@example.com',
          name: 'Unverified User',
          password_hash: 'hashedPassword',
          is_verified: false,
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
      expect(testRes.status).toHaveBeenCalledWith(403);
      expect(testRes.json).toHaveBeenCalledWith({
        success: false,
        error: 'Please verify your email address before logging in'
      });
    });
  });
});
