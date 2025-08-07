import { MockRequest, MockResponse } from '../types/express.types';
import { PoolClient } from 'pg';

export interface MockDb {
  query: jest.Mock;
  getClient: jest.Mock<Promise<PoolClient>, []>;
  close: jest.Mock<Promise<void>, []>;
  connect: jest.Mock<Promise<void>, []>;
}

/**
 * Creates a mock database instance with typed methods
 */
export const createMockDb = (): MockDb => {
  const mockDb: MockDb = {
    query: jest.fn(),
    getClient: jest.fn(),
    close: jest.fn(),
    connect: jest.fn(),
  };

  // Add mock implementations for the query method with proper typing
  const mockQuery = mockDb.query as jest.MockedFunction<typeof mockDb.query> & {
    mockResolvedValueOnce: <T>(value: T) => typeof mockQuery;
    mockRejectedValueOnce: (error: any) => typeof mockQuery;
    mockResolvedValue: <T>(value: T) => typeof mockQuery;
  };

  mockQuery.mockResolvedValueOnce = <T>(value: T) => {
    mockQuery.mockImplementationOnce(() => Promise.resolve(value as any));
    return mockQuery;
  };

  mockQuery.mockRejectedValueOnce = (error: any) => {
    mockQuery.mockImplementationOnce(() => Promise.reject(error));
    return mockQuery;
  };

  mockQuery.mockResolvedValue = <T>(value: T) => {
    mockQuery.mockImplementation(() => Promise.resolve(value as any));
    return mockQuery;
  };

  // Initialize with a default implementation
  mockQuery.mockImplementation(() => Promise.resolve({ rows: [], rowCount: 0 }));

  // Mock getClient to return a client with similar query method
  mockDb.getClient.mockResolvedValue({
    query: mockQuery,
    release: jest.fn(),
  } as unknown as PoolClient);

  return mockDb;
};

// Default mock database instance
export const mockDb = createMockDb();

/**
 * Resets all mocks to their initial state
 */
export const resetAllMocks = () => {
  mockDb.query.mockClear();
  mockDb.getClient.mockClear();
  mockDb.close.mockClear();
  mockDb.connect.mockClear();
  
  // Re-initialize the default mock implementation
  (mockDb.query as any).mockImplementation(() => Promise.resolve({ rows: [], rowCount: 0 }));
};
