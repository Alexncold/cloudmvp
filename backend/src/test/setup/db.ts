import { Database } from '../../services/database';
import { logger } from '../../utils/logger';
import { PoolConfig } from 'pg';

// In-memory SQLite configuration for testing
const testDbConfig: PoolConfig = {
  user: 'test',
  host: 'localhost',
  database: ':memory:',
  password: 'test',
  port: 5432,
};

// Create a test database instance
const testDb = new Database({
  ...testDbConfig,
  max: 1, // Single connection for testing
  idleTimeoutMillis: 1000,
  connectionTimeoutMillis: 1000,
  maxRetries: 1,
  retryDelay: 1000,
});

// Initialize test database with schema
async function initializeTestDatabase() {
  try {
    // Create tables and initial test data here
    await testDb.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        name VARCHAR(255),
        password_hash VARCHAR(255) NOT NULL,
        is_verified BOOLEAN DEFAULT false,
        verification_token VARCHAR(255),
        verification_token_expires TIMESTAMP,
        reset_password_token VARCHAR(255),
        reset_password_expires TIMESTAMP,
        refresh_token_hash VARCHAR(255),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        role VARCHAR(50) DEFAULT 'user'
      );
    `);
    
    logger.info('✅ Test database initialized');
  } catch (error) {
    logger.error('❌ Failed to initialize test database:', error);
    throw error;
  }
}

// Clean up test database
export async function cleanupTestDatabase() {
  try {
    await testDb.query('DROP TABLE IF EXISTS users CASCADE');
    await testDb.close();
    logger.info('✅ Test database cleaned up');
  } catch (error) {
    logger.error('❌ Failed to clean up test database:', error);
    throw error;
  }
}

export { testDb, initializeTestDatabase };
