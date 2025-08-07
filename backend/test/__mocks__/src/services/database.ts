import { QueryResult } from 'pg';

// Mock implementation of the database module
export const db = {
  query: jest.fn<Promise<QueryResult>, [string, any[]?]>(),
  getClient: jest.fn(),
  close: jest.fn(),
  connect: jest.fn()
};

export default db;
