// Simple mock for the database service
import { jest } from '@jest/globals';

// Create a simple mock client
const mockClient = {
  query: jest.fn(),
  release: jest.fn(),
  on: jest.fn(),
} as any; // Use type assertion to avoid complex type definitions

// Create mock functions
const mockQuery = jest.fn();
// @ts-ignore - Ignore TypeScript error for mockResolvedValue
const mockGetClient = jest.fn().mockResolvedValue(mockClient as never);
const mockClose = jest.fn();

// Create the mock database service
const mockDb = {
  query: mockQuery,
  getClient: mockGetClient,
  close: mockClose,
};

// Mock the database service module
jest.mock('../../../src/services/db', () => ({
  __esModule: true,
  db: mockDb,
  DatabaseService: jest.fn().mockImplementation(() => mockDb),
}));

export { mockDb as db, mockClient, mockQuery, mockGetClient, mockClose };
