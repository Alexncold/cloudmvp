import { Pool, PoolConfig } from 'pg';

class DatabaseService {
  private pool: Pool;

  constructor(config?: PoolConfig) {
    this.pool = new Pool({
      connectionString: process.env.DATABASE_URL,
      ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
      ...config
    });
  }

  async query(text: string, params?: any[]) {
    return this.pool.query(text, params);
  }

  async getClient() {
    return this.pool.connect();
  }

  async close() {
    await this.pool.end();
  }
}

// Export a singleton instance
export const db = new DatabaseService();

// Also export the class for testing
export { DatabaseService };
