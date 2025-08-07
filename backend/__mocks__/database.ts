// Manual mock for the database module
import { jest } from '@jest/globals';
import bcrypt from 'bcryptjs';

// Mock data
const testUsers: Record<string, any> = {};

// Helper to generate a test user
const createTestUser = async (email: string, password: string, name: string) => {
  const salt = await bcrypt.genSalt(10);
  const passwordHash = await bcrypt.hash(password, salt);
  const userId = `user-${Date.now()}-${Math.floor(Math.random() * 1000)}`;
  
  const user = {
    id: userId,
    email: email.toLowerCase(),
    name: name,
    password_hash: passwordHash,
    is_verified: true,
    created_at: new Date(),
    updated_at: new Date(),
    refresh_token_hash: null,
    verification_token: null,
    verification_token_expires: null,
    reset_token: null,
    reset_token_expires: null
  };
  
  testUsers[email.toLowerCase()] = user;
  return user;
};

const mockQuery = jest.fn();
const mockConnect = jest.fn();
const mockClose = jest.fn();

const mockDb = {
  query: mockQuery,
  connect: mockConnect,
  close: mockClose,
};

// Default mock implementations
mockQuery.mockImplementation(async (query: string, params: any[] = []) => {
  // Handle user registration
  if (query.includes('INSERT INTO users')) {
    const email = params[0];
    const name = params[1];
    const passwordHash = params[2];
    const verificationToken = params[3];
    
    // Create a new user
    const user = {
      id: `user-${Date.now()}-${Math.floor(Math.random() * 1000)}`,
      email: email.toLowerCase(),
      name,
      password_hash: passwordHash,
      is_verified: false,
      verification_token: verificationToken,
      verification_token_expires: new Date(Date.now() + 24 * 60 * 60 * 1000), // 24 hours from now
      created_at: new Date(),
      updated_at: new Date(),
      refresh_token_hash: null,
      reset_token: null,
      reset_token_expires: null
    };
    
    testUsers[email.toLowerCase()] = user;
    
    return {
      rows: [user],
      rowCount: 1,
      command: 'INSERT',
      oid: 0,
      fields: [],
    };
  }
  
  // Handle user lookup by email
  if (query.includes('SELECT * FROM users WHERE email = $1')) {
    const email = params[0]?.toLowerCase();
    const user = testUsers[email];
    
    return {
      rows: user ? [user] : [],
      rowCount: user ? 1 : 0,
      command: 'SELECT',
      oid: 0,
      fields: [],
    };
  }
  
  // Handle user update (e.g., during login)
  if (query.includes('UPDATE users SET refresh_token_hash')) {
    const refreshTokenHash = params[0];
    const userId = params[1];
    
    // Find and update the user
    const user = Object.values(testUsers).find(u => u.id === userId);
    if (user) {
      user.refresh_token_hash = refreshTokenHash;
      user.updated_at = new Date();
    }
    
    return {
      rows: user ? [user] : [],
      rowCount: user ? 1 : 0,
      command: 'UPDATE',
      oid: 0,
      fields: [],
    };
  }
  
  // Default response for other queries
  return {
    rows: [],
    rowCount: 0,
    command: '',
    oid: 0,
    fields: [],
  };
});

// Mock connection
mockConnect.mockResolvedValue({
  query: mockQuery,
  release: jest.fn().mockResolvedValue(undefined),
});

mockClose.mockResolvedValue(undefined);

// Helper to clear test users between tests
const clearTestUsers = () => {
  Object.keys(testUsers).forEach(key => delete testUsers[key]);
};

// Export the mock db and mock functions for test setup
export const __mockDb = mockDb;
export const __mockQuery = mockQuery;
export const __mockConnect = mockConnect;
export const __mockClose = mockClose;
export { clearTestUsers, createTestUser };

export default mockDb;
