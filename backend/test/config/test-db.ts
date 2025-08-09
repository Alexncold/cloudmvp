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
    // Mock the database initialization with production-like schema
    await mockDb.query(`
      CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
      
      CREATE TABLE IF NOT EXISTS users (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT,
        name TEXT NOT NULL,
        google_id TEXT UNIQUE,
        is_verified BOOLEAN DEFAULT FALSE,
        drive_connected BOOLEAN DEFAULT FALSE,
        google_refresh_token TEXT,
        verification_token TEXT,
        verification_token_expires TIMESTAMP WITH TIME ZONE,
        reset_token TEXT,
        reset_token_expires TIMESTAMP WITH TIME ZONE,
        refresh_token_hash TEXT,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        CONSTRAINT password_or_oauth CHECK (
          (password_hash IS NOT NULL) OR (google_id IS NOT NULL)
        )
      );
      
      CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
      CREATE INDEX IF NOT EXISTS idx_users_google_id ON users(google_id);
    `);
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
