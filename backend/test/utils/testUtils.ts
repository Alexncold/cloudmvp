import { Pool } from 'pg';
import { execSync } from 'child_process';
import { config } from 'dotenv';
import path from 'path';

// Load test environment variables
config({ path: path.resolve(__dirname, '../../.env.test') });

// Test database configuration
const TEST_DB_URL = process.env.TEST_DATABASE_URL || 'postgresql://postgres:postgres@localhost:5432/cloudcam_test';

// Create a new pool with a connection limit of 1 for testing
const pool = new Pool({
  connectionString: TEST_DB_URL,
  max: 1, // Use a single connection for tests to avoid race conditions
  idleTimeoutMillis: 10000,
  connectionTimeoutMillis: 2000,
});

/**
 * Set up the test database by running migrations
 */
export async function setupTestDatabase() {
  try {
    // Create a new database connection
    const client = await pool.connect();
    
    // Run migrations
    await client.query('BEGIN');
    
    // Run each migration file in order
    const migrations = [
      path.join(__dirname, '../../database/migrations/001_initial_schema.sql'),
      path.join(__dirname, '../../database/migrations/002_add_user_drive_fields.sql'),
    ];
    
    for (const migration of migrations) {
      const migrationPath = path.resolve(__dirname, migration);
      const migrationSQL = require('fs').readFileSync(migrationPath, 'utf8');
      await client.query(migrationSQL);
    }
    
    await client.query('COMMIT');
    client.release();
    
    console.log('✅ Test database migrated successfully');
  } catch (error) {
    console.error('❌ Failed to migrate test database:', error);
    throw error;
  }
}

/**
 * Clean up the test database by dropping all tables
 */
export async function teardownTestDatabase() {
  try {
    const client = await pool.connect();
    await client.query(`
      DROP SCHEMA public CASCADE;
      CREATE SCHEMA public;
      GRANT ALL ON SCHEMA public TO postgres;
      GRANT ALL ON SCHEMA public TO public;
    `);
    client.release();
    console.log('✅ Test database cleaned up');
  } catch (error) {
    console.error('❌ Failed to clean up test database:', error);
    throw error;
  } finally {
    await pool.end();
  }
}

/**
 * Create a test user in the database
 */
export async function createTestUser(userData = {}) {
  const defaultUser = {
    email: 'test@example.com',
    password: 'Test@123', // Will be hashed
    name: 'Test User',
    is_active: true,
    ...userData
  };
  
  const client = await pool.connect();
  try {
    const result = await client.query(
      `INSERT INTO users (email, password, name, is_active, created_at, updated_at)
       VALUES ($1, $2, $3, $4, NOW(), NOW())
       RETURNING id, email, name, is_active`,
      [defaultUser.email, defaultUser.password, defaultUser.name, defaultUser.is_active]
    );
    return result.rows[0];
  } finally {
    client.release();
  }
}

/**
 * Generate a JWT token for testing
 */
export function generateTestToken(userId: string, expiresIn = '1h') {
  const jwt = require('jsonwebtoken');
  const secret = process.env.JWT_SECRET || 'test-secret';
  
  return jwt.sign(
    { userId, type: 'access' },
    secret,
    { expiresIn }
  );
}

/**
 * Wait for a specified number of milliseconds
 */
export function wait(ms: number) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

export default {
  setupTestDatabase,
  teardownTestDatabase,
  createTestUser,
  generateTestToken,
  wait,
  pool
};
