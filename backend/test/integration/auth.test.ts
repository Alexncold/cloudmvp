import axios, { AxiosError } from 'axios';
import { v4 as uuidv4 } from 'uuid';
import { logger } from '../../src/utils/logger';
import { setupTestDatabase, teardownTestDatabase, createTestUser, generateTestToken } from '../utils/testUtils';

// Configuration
// Use the environment variable or default to the actual backend port (3001)
const API_BASE_URL = process.env.API_URL || 'http://127.0.0.1:3001';
const TEST_EMAIL = `test-${uuidv4().substring(0, 8)}@test.com`;
const TEST_PASSWORD = 'TestPassword123!';
const TEST_NAME = 'Test User';

// Debug logging
console.log(`[TEST] Using API URL: ${API_BASE_URL}`);
console.log(`[TEST] NODE_ENV: ${process.env.NODE_ENV}`);
console.log(`[TEST] DATABASE_URL: ${process.env.DATABASE_URL ? 'set' : 'not set'}`);

// Variables to store tokens and test data
let accessToken = '';
let refreshToken = '';
let testUserId = '';

// Configured HTTP client
const api = axios.create({
  baseURL: `${API_BASE_URL}/api`,
  validateStatus: (status) => status < 500, // Don't throw for 4xx errors
});

// Request interceptor for logging
api.interceptors.request.use((config) => {
  logger.debug(`[TEST] ${config.method?.toUpperCase()} ${config.url}`);
  if (config.data) {
    logger.debug('[TEST] Request Data:', JSON.stringify(config.data, null, 2));
  }
  return config;
});

// Response interceptor for logging
api.interceptors.response.use(
  (response) => {
    logger.debug(`[TEST] Response ${response.status}:`, JSON.stringify(response.data, null, 2));
    return response;
  },
  (error) => {
    logger.error('[TEST] Error:', error.message);
    return Promise.reject(error);
  }
);

// Simple test to verify test execution
describe('Test Suite', () => {
  it('should run a simple test', () => {
    console.log('This is a simple test running');
    expect(true).toBe(true);
  });
});

// Helper function to wait
const delay = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));

// Set auth header for authenticated requests
const setAuthHeader = (token: string) => {
  api.defaults.headers.common['Authorization'] = `Bearer ${token}`;
};

// Clear auth header
const clearAuthHeader = () => {
  delete api.defaults.headers.common['Authorization'];
};

describe('Authentication System', () => {
  // Setup and teardown
  beforeAll(async () => {
    await setupTestDatabase();
  });

  afterAll(async () => {
    await teardownTestDatabase();
  });

  afterEach(() => {
    // Clear auth header after each test
    clearAuthHeader();
  });

  // Test 1: User Registration
  test('should register a new user', async () => {
    const response = await api.post('/auth/register', {
      email: TEST_EMAIL,
      password: TEST_PASSWORD,
      name: TEST_NAME,
    });

    expect(response.status).toBe(201);
    expect(response.data).toHaveProperty('success', true);
    expect(response.data).toHaveProperty('message', 'User registered successfully');
    expect(response.data).toHaveProperty('user.email', TEST_EMAIL);
    expect(response.data.user).not.toHaveProperty('password');
    
    // Save user ID for future tests
    testUserId = response.data.user.id;
  });

  // Test 2: Login with registered user
  test('should login with valid credentials', async () => {
    const response = await api.post('/auth/login', {
      email: TEST_EMAIL,
      password: TEST_PASSWORD,
    });

    expect(response.status).toBe(200);
    expect(response.data).toHaveProperty('success', true);
    expect(response.data).toHaveProperty('accessToken');
    expect(response.data).toHaveProperty('refreshToken');
    expect(response.data).toHaveProperty('user');
    
    // Save tokens for future tests
    accessToken = response.data.accessToken;
    refreshToken = response.data.refreshToken;
    
    // Set auth header for subsequent requests
    setAuthHeader(accessToken);
  });

  // Test 3: Get current user profile
  test('should get current user profile', async () => {
    const response = await api.get('/auth/me');
    
    expect(response.status).toBe(200);
    expect(response.data).toHaveProperty('success', true);
    expect(response.data).toHaveProperty('user.email', TEST_EMAIL);
    expect(response.data.user).not.toHaveProperty('password');
  });

  // Test 4: Refresh access token
  test('should refresh access token with valid refresh token', async () => {
    const response = await api.post('/auth/refresh-token', {
      refreshToken,
    });
    
    expect(response.status).toBe(200);
    expect(response.data).toHaveProperty('success', true);
    expect(response.data).toHaveProperty('accessToken');
    
    // Update access token
    accessToken = response.data.accessToken;
    setAuthHeader(accessToken);
  });

  // Test 5: Logout
  test('should logout and invalidate tokens', async () => {
    const response = await api.post('/auth/logout');
    
    expect(response.status).toBe(200);
    expect(response.data).toHaveProperty('success', true);
    
    // Verify token is invalidated
    clearAuthHeader();
    setAuthHeader(accessToken);
    
    const meResponse = await api.get('/auth/me').catch(error => error.response || error);
    expect(meResponse.status).toBe(401);
  });

  // Test 6: Rate limiting
  test('should enforce rate limiting on login attempts', async () => {
    // Make multiple login attempts with wrong password
    const promises = [];
    for (let i = 0; i < 15; i++) {
      promises.push(
        api.post('/auth/login', {
          email: TEST_EMAIL,
          password: 'wrongpassword',
        }).catch(error => error.response || error)
      );
    }
    
    const responses = await Promise.all(promises);
    
    // Verify that some requests were rate limited (status 429)
    const rateLimitedResponses = responses.filter(r => r.status === 429);
    expect(rateLimitedResponses.length).toBeGreaterThan(0);
    
    // Verify error message for rate limited requests
    if (rateLimitedResponses.length > 0) {
      expect(rateLimitedResponses[0].data).toHaveProperty('success', false);
      expect(rateLimitedResponses[0].data).toHaveProperty('message');
      expect(rateLimitedResponses[0].data.message).toMatch(/too many requests/i);
    }
  });

  // Test 7: Password reset flow
  test('should handle password reset request', async () => {
    const response = await api.post('/auth/forgot-password', {
      email: TEST_EMAIL
    });
    
    // Note: In test environment, we might not actually send an email
    // So we just verify the endpoint responds with success
    expect([200, 201, 202]).toContain(response.status);
    expect(response.data).toHaveProperty('success', true);
    expect(response.data).toHaveProperty('message');
  });

  // Test 8: Invalid token handling
  test('should reject invalid tokens', async () => {
    // Set an invalid token
    setAuthHeader('invalid-token');
    
    const response = await api.get('/auth/me').catch(error => error.response || error);
    
    expect(response.status).toBe(401);
    expect(response.data).toHaveProperty('success', false);
    expect(response.data).toHaveProperty('message');
  });

  // Test 9: Registration with existing email
  test('should not allow duplicate email registration', async () => {
    const response = await api.post('/auth/register', {
      email: TEST_EMAIL,
      password: 'AnotherPassword123!',
      name: 'Duplicate User'
    });
    
    expect(response.status).toBe(400);
    expect(response.data).toHaveProperty('success', false);
    expect(response.data).toHaveProperty('message');
    expect(response.data.message).toMatch(/already exists/i);
  });

  // Test 10: Login with invalid credentials
  test('should reject login with invalid credentials', async () => {
    const response = await api.post('/auth/login', {
      email: TEST_EMAIL,
      password: 'wrongpassword'
    }).catch(error => error.response || error);
    
    expect(response.status).toBe(401);
    expect(response.data).toHaveProperty('success', false);
    expect(response.data).toHaveProperty('message');
  });

  // Test 11: Access protected route without token
  test('should reject unauthenticated access to protected routes', async () => {
    clearAuthHeader();
    const response = await api.get('/auth/me').catch(error => error.response || error);
    
    expect(response.status).toBe(401);
    expect(response.data).toHaveProperty('success', false);
    expect(response.data).toHaveProperty('message');
  });

  // Test 12: Refresh token with invalid token
  test('should reject invalid refresh token', async () => {
    const response = await api.post('/auth/refresh-token', {
      refreshToken: 'invalid-refresh-token'
    }).catch(error => error.response || error);
    
    expect(response.status).toBe(401);
    expect(response.data).toHaveProperty('success', false);
    expect(response.data).toHaveProperty('message');
  });
});
