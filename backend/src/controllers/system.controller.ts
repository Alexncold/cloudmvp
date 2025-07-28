import { Request, Response } from 'express';
import { logger } from '../utils/logger';
import { db } from '../database/db';
import { StorageService } from '../services/storage.service';

class SystemController {
  /**
   * Health check endpoint
   */
  public async healthCheck(req: Request, res: Response): Promise<void> {
    const checks = {
      database: false,
      storage: false,
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
    };

    try {
      // Check database connection
      await db.one('SELECT 1');
      checks.database = true;
    } catch (error) {
      logger.error('Database health check failed:', error);
    }

    try {
      // Check storage
      await StorageService.getStorageUsage();
      checks.storage = true;
    } catch (error) {
      logger.error('Storage health check failed:', error);
    }

    const status = checks.database && checks.storage ? 'healthy' : 'degraded';
    
    res.status(status === 'healthy' ? 200 : 503).json({
      status,
      ...checks,
    });
  }

  /**
   * System information endpoint
   */
  public async systemInfo(req: Request, res: Response): Promise<void> {
    try {
      // Get database version
      const dbVersion = await db.one('SELECT version()');
      
      // Get storage usage
      const storageUsage = await StorageService.getStorageUsage();
      const storageUsageMB = Math.round(storageUsage / (1024 * 1024) * 100) / 100;
      const maxStorageMB = parseInt(process.env.MAX_STORAGE_GB || '10') * 1024;
      const storageUsagePercent = Math.round((storageUsageMB / (maxStorageMB * 1024)) * 100);

      res.json({
        node: {
          version: process.version,
          platform: process.platform,
          memoryUsage: process.memoryUsage(),
          uptime: process.uptime(),
        },
        database: {
          version: dbVersion.version,
          maxConnections: await this.getMaxConnections(),
          activeConnections: await this.getActiveConnections(),
        },
        storage: {
          usedMB: storageUsageMB,
          maxMB: maxStorageMB * 1024,
          usagePercent: storageUsagePercent,
          path: process.env.STORAGE_DIR,
        },
        environment: process.env.NODE_ENV,
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      logger.error('Failed to get system info:', error);
      res.status(500).json({
        error: 'Failed to retrieve system information',
        details: process.env.NODE_ENV === 'development' ? error.message : undefined,
      });
    }
  }

  /**
   * Get database max connections
   */
  private async getMaxConnections(): Promise<number> {
    try {
      const result = await db.one('SHOW max_connections');
      return parseInt(result.max_connections, 10);
    } catch (error) {
      logger.error('Failed to get max connections:', error);
      return -1;
    }
  }

  /**
   * Get active database connections
   */
  private async getActiveConnections(): Promise<number> {
    try {
      const result = await db.one(
        'SELECT count(*) as count FROM pg_stat_activity WHERE datname = $1',
        [process.env.POSTGRES_DB]
      );
      return parseInt(result.count, 10);
    } catch (error) {
      logger.error('Failed to get active connections:', error);
      return -1;
    }
  }
}

export const systemController = new SystemController();
