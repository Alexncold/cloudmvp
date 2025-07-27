import { Pool, PoolConfig } from 'pg';
import { logger } from '../../src/utils/logger';
import { db as mockDb } from '../__mocks__/db';

// Configuration for test database (using mock)
const testDbConfig: PoolConfig = {
  user: 'test',
  host: 'localhost',
  database: 'test_db',
  password: 'test',
  port: 5432,
};

// Create a mock database connection pool
const testPool = {
  connect: async () => ({
    query: mockDb.query,
    release: jest.fn(),
  }),
  query: mockDb.query,
  end: jest.fn(),
} as unknown as Pool;

// Function to initialize test database
async function initializeTestDatabase() {
  try {
    // Mock the database initialization
    await mockDb.query('CREATE TABLE IF NOT EXISTS users (id SERIAL PRIMARY KEY, email VARCHAR(255) UNIQUE NOT NULL)');
    logger.info('✅ Test database initialized successfully');
  } catch (error) {
    logger.error('❌ Failed to initialize test database:', error);
    throw error;
  }
}

// Function to clean up test database
async function cleanupTestDatabase() {
  try {
    // Clean up any test data
    await mockDb.query('DROP TABLE IF EXISTS users CASCADE');
    logger.info('✅ Test database cleaned up successfully');
  } catch (error) {
    logger.error('❌ Failed to clean up test database:', error);
    throw error;
  }
}

export { testPool, initializeTestDatabase, cleanupTestDatabase };
