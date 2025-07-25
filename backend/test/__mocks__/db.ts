// Mock implementation of the database service for testing
class MockDatabaseService {
  private mockResponses: Map<string, any> = new Map();
  
  // Mock implementation of the query method
  async query(text: string, params?: any[]) {
    // Check if we have a mock response for this query
    const mockResponse = this.mockResponses.get(text);
    if (mockResponse) {
      if (typeof mockResponse === 'function') {
        return mockResponse(params);
      }
      return mockResponse;
    }
    
    // Default mock response for queries without a specific mock
    return { rows: [], rowCount: 0 };
  }
  
  // Mock implementation of getClient
  async getClient() {
    return {
      query: this.query.bind(this),
      release: jest.fn(),
    };
  }
  
  // Mock implementation of close
  async close() {
    return Promise.resolve();
  }
  
  // Helper method to set mock responses for specific queries
  setMockResponse(query: string, response: any) {
    this.mockResponses.set(query, response);
  }
  
  // Helper method to clear all mock responses
  clearMocks() {
    this.mockResponses.clear();
  }
}

// Create a singleton instance for testing
export const db = new MockDatabaseService();

// Also export the class for testing
export { MockDatabaseService as DatabaseService };
