// Mock implementation of the database service for testing
import { Pool, QueryResult, QueryResultRow } from 'pg';

// Mock the pg module
jest.mock('pg', () => {
  const mPool = {
    query: jest.fn(),
    connect: jest.fn(),
    end: jest.fn(),
    on: jest.fn(),
  };
  return { Pool: jest.fn(() => mPool) };
});

// Create a mock database instance
export const mockDb = {
  query: jest.fn(),
  connect: jest.fn(),
  close: jest.fn(),
};

// Mock the database module
export const setupMockDatabase = () => {
  // Mock the database.query method
  mockDb.query.mockImplementation((query: string, params?: any[]): Promise<QueryResult> => {
    // Handle specific queries used in tests
    if (query.includes('SELECT * FROM users WHERE email')) {
      return Promise.resolve({
        rows: [], // No user found by default
        rowCount: 0,
        command: 'SELECT',
        oid: 0,
        fields: [],
      });
    }
    
    // Handle INSERT queries
    if (query.startsWith('INSERT INTO users')) {
      return Promise.resolve({
        rows: [{
          id: 1,
          email: params?.[0] || 'test@example.com',
          name: 'Test User',
          is_verified: false,
          role: 'user',
          created_at: new Date(),
          updated_at: new Date(),
        }],
        rowCount: 1,
        command: 'INSERT',
        oid: 0,
        fields: [],
      });
    }
    
    // Default response for other queries
    return Promise.resolve({
      rows: [],
      rowCount: 0,
      command: '',
      oid: 0,
      fields: [],
    });
  });
  
  // Mock the connect method
  mockDb.connect.mockResolvedValue({
    query: mockDb.query,
    release: jest.fn(),
  });
  
  // Mock the close method
  mockDb.close.mockResolvedValue(undefined);
  
  return mockDb;
};

// Reset all mocks before each test
export const resetMockDatabase = () => {
  mockDb.query.mockClear();
  mockDb.connect.mockClear();
  mockDb.close.mockClear();
};

export default mockDb;
