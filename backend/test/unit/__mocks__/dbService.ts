// Mock implementation of the database service for unit tests

class MockClient {
  query = jest.fn();
  release = jest.fn();

  constructor() {
    // Default mock implementation
    this.query.mockResolvedValue({ rows: [], rowCount: 0 });
  }
}

class MockDatabaseService {
  query = jest.fn();
  getClient = jest.fn();
  close = jest.fn();
  
  constructor() {
    // Default mock implementation
    const client = new MockClient();
    this.query.mockResolvedValue({ rows: [], rowCount: 0 });
    this.getClient.mockResolvedValue(client);
    this.close.mockResolvedValue(undefined);
  }
}

// Create a singleton instance
export const db = new MockDatabaseService();

// Export the mock client for testing
export const mockClient = new MockClient();

// Export the class for testing
export { MockDatabaseService as DatabaseService };
