import { Pool, PoolConfig, QueryResult, QueryResultRow } from 'pg';
import { logger } from '../utils/logger';

export interface DatabaseConfig extends PoolConfig {
  maxRetries?: number;
  retryDelay?: number;
}

class Database {
  private pool: Pool;
  private config: DatabaseConfig;
  private retryCount = 0;

  constructor(config: DatabaseConfig) {
    this.config = {
      ...config,
      maxRetries: config.maxRetries ?? 3,
      retryDelay: config.retryDelay ?? 5000, // 5 segundos
    };
    
    this.pool = new Pool(this.config);
    this.setupEventListeners();
  }

  private setupEventListeners() {
    this.pool.on('connect', () => {
      logger.info('✅ Database connection established');
      this.retryCount = 0; // Reset retry counter on successful connection
    });

    this.pool.on('error', (err) => {
      logger.error('❌ Unexpected database error:', err);
      this.handleConnectionError();
    });
  }

  private async handleConnectionError() {
    this.retryCount++;
    
    if (this.retryCount <= (this.config.maxRetries || 3)) {
      logger.warn(`⏳ Attempting to reconnect to database (${this.retryCount}/${this.config.maxRetries})...`);
      await new Promise(resolve => setTimeout(resolve, this.config.retryDelay));
      this.pool = new Pool(this.config);
      this.setupEventListeners();
    } else {
      logger.error('❌ Max database connection retries reached. Please check your database configuration.');
      process.exit(1);
    }
  }

  public async query<T extends QueryResultRow = any>(text: string, params?: any[]): Promise<QueryResult<T>> {
    try {
      const start = Date.now();
      const res = await this.pool.query(text, params);
      const duration = Date.now() - start;
      
      logger.debug('Executed query', {
        query: text,
        duration: `${duration}ms`,
        rows: res.rowCount
      });
      
      return res;
    } catch (error) {
      logger.error('Database query error:', {
        error: error instanceof Error ? error.message : 'Unknown error',
        query: text,
        params: params ? JSON.stringify(params) : 'none'
      });
      throw error;
    }
  }

  public async connect() {
    try {
      const client = await this.pool.connect();
      logger.info('✅ Successfully connected to database');
      return client;
    } catch (error) {
      logger.error('❌ Could not connect to database:', error);
      await this.handleConnectionError();
      throw error;
    }
  }

  public async close() {
    await this.pool.end();
    logger.info('Database pool has ended');
  }
}

// Configuración de la base de datos
const dbConfig: DatabaseConfig = {
  connectionString: process.env.DATABASE_URL,
  max: parseInt(process.env.DB_POOL_MAX || '20', 10),
  idleTimeoutMillis: parseInt(process.env.DB_IDLE_TIMEOUT_MS || '30000', 10),
  connectionTimeoutMillis: parseInt(process.env.DB_CONNECTION_TIMEOUT_MS || '2000', 10),
  maxRetries: parseInt(process.env.DB_MAX_RETRIES || '3', 10),
  retryDelay: parseInt(process.env.DB_RETRY_DELAY_MS || '5000', 10)
};

const db = new Database(dbConfig);

// Probar conexión al inicio
db.connect().catch(error => {
  logger.error('Failed to establish database connection:', error);
  process.exit(1);
});

export { db };
