import { MockRequest, MockResponse } from '../types/express.types';
import { PoolClient } from 'pg';
import { Request, Response } from 'express';

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
 * Creates a mock Request object for testing
 */
export function createMockRequest(overrides: Partial<MockRequest> = {}): MockRequest {
  return {
    body: {},
    params: {},
    query: {},
    cookies: {},
    header: jest.fn(),
    ...overrides,
  } as MockRequest;
}

/**
 * Creates a mock Response object for testing
 */
export function createMockResponse(): MockResponse {
  const res: any = {};
  
  // Mock common response methods
  res.status = jest.fn().mockReturnValue(res);
  res.json = jest.fn().mockReturnValue(res);
  res.send = jest.fn().mockReturnValue(res);
  res.sendStatus = jest.fn().mockReturnValue(res);
  res.cookie = jest.fn().mockReturnValue(res);
  res.clearCookie = jest.fn().mockReturnValue(res);
  res.setHeader = jest.fn().mockReturnValue(res);
  res.getHeader = jest.fn().mockReturnValue(undefined);
  res.removeHeader = jest.fn().mockReturnValue(res);
  res.redirect = jest.fn().mockReturnValue(res);
  
  // Add locals property
  res.locals = {};
  
  return res as MockResponse;
}

/**
 * Creates a mock NextFunction for testing
 */
export function createMockNext(): jest.Mock {
  return jest.fn();
}

/**
 * Resets all mocks to their initial state
 */
export function resetAllMocks() {
  mockDb.query.mockReset();
  mockDb.getClient.mockReset();
  mockDb.close.mockReset();
  mockDb.connect.mockReset();
  
  // Reset any other global mocks here
  jest.clearAllMocks();
  
  // Re-initialize the default mock implementation
  (mockDb.query as any).mockImplementation(() => Promise.resolve({ rows: [], rowCount: 0 }));
}
