// Mocks para la base de datos

type QueryResult = {
  rows: any[];
  rowCount: number;
};

type MockClient = {
  query: jest.Mock<Promise<QueryResult>, [string, any[]]>;
  release: jest.Mock;
  on: jest.Mock;
  queryQueue: Array<{query: string, params?: any[], resolve: Function, reject: Function}>;
};

const createMockClient = (): MockClient => {
  const mockQuery = jest.fn();
  const mockRelease = jest.fn().mockImplementation(function(this: MockClient) {
    this.release.mockClear();
    this.query.mockClear();
  });
  const mockOn = jest.fn();
  
  return {
    query: mockQuery,
    release: mockRelease,
    on: mockOn,
    queryQueue: []
  };
};

const mockPool = {
  connect: jest.fn().mockImplementation(() => {
    const client = createMockClient();
    // Default mock query implementation
    client.query.mockImplementation((query: string, params?: any[]) => {
      return Promise.resolve({ rows: [], rowCount: 0 });
    });
    return Promise.resolve(client);
  }),
  query: jest.fn().mockResolvedValue({ rows: [], rowCount: 0 }),
  end: jest.fn().mockResolvedValue(undefined),
};

// Mock para el módulo 'pg'
jest.mock('pg', () => {
  const pg = jest.requireActual('pg');
  return {
    ...pg,
    Pool: jest.fn().mockImplementation(() => ({
      ...mockPool,
      // Ensure we return a new instance with the same implementation
      connect: mockPool.connect,
      query: mockPool.query,
      end: mockPool.end,
    })),
  };
});

// Reset all mocks before each test
beforeEach(() => {
  jest.clearAllMocks();
  
  // Reset the default mock implementation
  mockPool.connect.mockImplementation(() => {
    const client = createMockClient();
    client.query.mockImplementation((query: string, params?: any[]) => {
      return Promise.resolve({ rows: [], rowCount: 0 });
    });
    return Promise.resolve(client);
  });
  
  mockPool.query.mockResolvedValue({ rows: [], rowCount: 0 });
  mockPool.end.mockResolvedValue(undefined);
});

export { mockPool, createMockClient };
