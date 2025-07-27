// Manual mock for the database module
import { jest } from '@jest/globals';

const mockQuery = jest.fn();
const mockConnect = jest.fn();
const mockClose = jest.fn();

const mockDb = {
  query: mockQuery,
  connect: mockConnect,
  close: mockClose,
};

// Default mock implementations
mockQuery.mockImplementation((query: string, params?: any[]) => {
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
  
  // Default response for other queries
  return Promise.resolve({
    rows: [],
    rowCount: 0,
    command: '',
    oid: 0,
    fields: [],
  });
});

mockConnect.mockResolvedValue({
  query: mockQuery,
  release: jest.fn(),
});

mockClose.mockResolvedValue(undefined);

// Export the mock db and mock functions for test setup
export const __mockDb = mockDb;
export const __mockQuery = mockQuery;
export const __mockConnect = mockConnect;
export const __mockClose = mockClose;

export default mockDb;
