import { Pool, PoolConfig } from 'pg';
import { logger } from '../utils/logger';
import fs from 'fs';
import path from 'path';

// Default configuration for production
const DEFAULT_POOL_CONFIG = {
  max: parseInt(process.env.DB_POOL_MAX || '20', 10), // Maximum number of clients in the pool
  min: 2,  // Minimum number of clients to keep in the pool
  idleTimeoutMillis: 30000, // Close idle clients after 30 seconds
  connectionTimeoutMillis: 5000, // Return an error after 5 seconds if connection could not be established
  query_timeout: 10000, // 10 seconds query timeout
  statement_timeout: 10000, // 10 seconds statement timeout
  idle_in_transaction_session_timeout: 30000, // 30 seconds idle in transaction timeout
};

class DatabaseService {
  private pool: Pool;
  private isProduction: boolean;
  private isConnected: boolean = false;

  constructor(config: PoolConfig = {}) {
    try {
      if (!process.env.DATABASE_URL) {
        throw new Error('DATABASE_URL is not defined in environment variables');
      }

      this.isProduction = process.env.NODE_ENV === 'production';
      
      // Parse DATABASE_URL for SSL configuration
      const sslConfig = this.getSSLConfig();

      this.pool = new Pool({
        ...DEFAULT_POOL_CONFIG,
        connectionString: process.env.DATABASE_URL,
        ssl: sslConfig,
        ...config, // Allow overrides
      });

      this.setupEventListeners();
      this.testConnection().catch(error => {
        logger.error('Failed to establish database connection:', error);
        process.exit(1);
      });
    } catch (error) {
      logger.error('Error initializing database service:', error);
      throw error;
    }
  }

  private getSSLConfig() {
    if (!this.isProduction) {
      return this.shouldUseSSL() ? { rejectUnauthorized: false } : false;
    }

    // In production, always use SSL with certificate verification
    const sslConfig: any = {
      rejectUnauthorized: true,
    };

    // Check for custom CA certificate
    const caPath = process.env.DB_CA_CERT_PATH;
    if (caPath) {
      try {
        sslConfig.ca = fs.readFileSync(path.resolve(caPath)).toString();
      } catch (error) {
        logger.error('Failed to read database CA certificate:', error);
        throw new Error('Failed to read database CA certificate');
      }
    }

    return sslConfig;
  }

  private async testConnection() {
    try {
      const client = await this.pool.connect();
      await client.query('SELECT 1 as test');
      client.release();
      this.isConnected = true;
      logger.info('✅ Database connection established successfully');
    } catch (error) {
      this.isConnected = false;
      logger.error('❌ Database connection failed:', error);
      throw error;
    }
  }

  private shouldUseSSL(): boolean {
    // Check if DATABASE_URL has ?sslmode=require or DB_SSL env var is set to 'true'
    const dbUrl = process.env.DATABASE_URL || '';
    const useSSL = process.env.DB_SSL || '';
    return dbUrl.includes('sslmode=require') || useSSL.toLowerCase() === 'true';
  }

  private setupEventListeners() {
    this.pool.on('connect', (client) => {
      // Set statement timeout for all queries on this client
      client.query('SET statement_timeout = 10000');
      client.query('SET idle_in_transaction_session_timeout = 30000');
    });

    this.pool.on('error', (err) => {
      logger.error('Unexpected error on idle PostgreSQL client', { error: err });
      // In production, you might want to restart the process
      if (this.isProduction) {
        process.exit(-1);
      }
    });
  }

  async query(text: string, params: any[] = [], timeout = 10000) {
    if (!this.isConnected) {
      throw new Error('Database is not connected');
    }

    const start = Date.now();
    const client = await this.pool.connect();
    
    try {
      // Set statement timeout for this transaction
      await client.query(`SET LOCAL statement_timeout = ${timeout}`);
      
      const res = await client.query({
        text,
        values: params,
        rowMode: 'array',
      });
      
      const duration = Date.now() - start;
      
      // Log slow queries
      if (duration > 200) { // Log queries slower than 200ms
        logger.warn('Slow query', {
          duration,
          query: text,
          params: this.isProduction ? null : params, // Don't log params in production
        });
      }
      
      return res;
    } catch (error: unknown) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown database error';
      const errorDetails = {
        error: errorMessage,
        query: text,
        params: this.isProduction ? null : params,
        stack: error instanceof Error ? error.stack : undefined,
      };
      
      // Log more detailed error information
      if (error instanceof Error && 'code' in error) {
        logger.error(`Database error (${error.code}):`, errorDetails);
      } else {
        logger.error('Database error:', errorDetails);
      }
      
      throw error;
    } finally {
      client.release();
    }
  }

  async getClient() {
    const client = await this.pool.connect();
    
    // Set a timeout for how long a client can be kept checked out
    const timeout = setTimeout(() => {
      logger.error('Client has been checked out for too long!');
      client.release(new Error('Client checkout timeout'));
    }, 30000); // 30 seconds

    // Override the release method to clear the timeout
    const release = client.release;
    client.release = (err?: Error) => {
      clearTimeout(timeout);
      return release.call(client, err);
    };

    return client;
  }

  async close() {
    try {
      await this.pool.end();
      logger.info('Database pool has ended');
    } catch (error) {
      logger.error('Error closing database pool', { error });
      throw error;
    }
  }
}

// Export a singleton instance
export const db = new DatabaseService();

// Also export the class for testing
export { DatabaseService };
