import fs from 'fs';
import path from 'path';
import { promisify } from 'util';
import { logger } from '../utils/logger';

const readdir = promisify(fs.readdir);
const stat = promisify(fs.stat);
const unlink = promisify(fs.unlink);
const mkdir = promisify(fs.mkdir);
const access = promisify(fs.access);

interface FileInfo {
  path: string;
  size: number;
  createdAt: Date;
}

export class StorageService {
  private static readonly STORAGE_DIR = process.env.STORAGE_DIR || './storage';
  private static readonly MAX_STORAGE_MB = parseInt(process.env.MAX_STORAGE_MB || '1024'); // Default 1GB
  private static readonly CLEANUP_THRESHOLD = 0.8; // Cleanup when storage reaches 80% of max

  /**
   * Initializes the storage directory
   */
  public static async initialize(): Promise<void> {
    try {
      await this.ensureDirectoryExists(this.STORAGE_DIR);
      logger.info(`Storage service initialized at ${path.resolve(this.STORAGE_DIR)}`);
    } catch (error) {
      logger.error('Failed to initialize storage service:', error);
      throw new Error('Failed to initialize storage service');
    }
  }

  /**
   * Ensures a directory exists, creates it if it doesn't
   */
  private static async ensureDirectoryExists(dirPath: string): Promise<void> {
    try {
      await access(dirPath);
    } catch (error) {
      if (error.code === 'ENOENT') {
        // Directory doesn't exist, create it
        await mkdir(dirPath, { recursive: true });
      } else {
        throw error;
      }
    }
  }

  /**
   * Gets the current storage usage in bytes
   */
  public static async getStorageUsage(): Promise<number> {
    try {
      const files = await this.getAllFiles(this.STORAGE_DIR);
      return files.reduce((total, file) => total + file.size, 0);
    } catch (error) {
      logger.error('Error getting storage usage:', error);
      throw new Error('Failed to get storage usage');
    }
  }

  /**
   * Gets the current storage usage as a percentage of the maximum
   */
  public static async getStorageUsagePercentage(): Promise<number> {
    const usageBytes = await this.getStorageUsage();
    const maxBytes = this.MAX_STORAGE_MB * 1024 * 1024; // Convert MB to bytes
    return (usageBytes / maxBytes) * 100;
  }

  /**
   * Gets all files in a directory recursively
   */
  private static async getAllFiles(dir: string): Promise<FileInfo[]> {
    const files: FileInfo[] = [];
    
    try {
      const entries = await readdir(dir, { withFileTypes: true });
      
      for (const entry of entries) {
        const fullPath = path.join(dir, entry.name);
        
        if (entry.isDirectory()) {
          // Recursively get files in subdirectories
          const subFiles = await this.getAllFiles(fullPath);
          files.push(...subFiles);
        } else if (entry.isFile()) {
          // Get file stats
          const stats = await stat(fullPath);
          files.push({
            path: fullPath,
            size: stats.size,
            createdAt: stats.birthtime || stats.ctime
          });
        }
      }
    } catch (error) {
      if (error.code !== 'ENOENT') { // Ignore "directory doesn't exist" errors
        logger.error(`Error reading directory ${dir}:`, error);
      }
    }
    
    return files;
  }

  /**
   * Cleans up old files to free up space
   */
  public static async cleanupOldFiles(): Promise<void> {
    try {
      const usagePercent = await this.getStorageUsagePercentage();
      
      // Only clean up if we're above the threshold
      if (usagePercent < this.CLEANUP_THRESHOLD * 100) {
        return;
      }
      
      logger.info(`Storage usage at ${usagePercent.toFixed(2)}%, cleaning up old files...`);
      
      // Get all files sorted by creation date (oldest first)
      const allFiles = await this.getAllFiles(this.STORAGE_DIR);
      const sortedFiles = allFiles.sort((a, b) => 
        a.createdAt.getTime() - b.createdAt.getTime()
      );
      
      // Delete files until we're below the threshold
      let deletedSize = 0;
      const targetSize = (this.MAX_STORAGE_MB * this.CLEANUP_THRESHOLD * 0.9) * 1024 * 1024; // 90% of threshold
      
      for (const file of sortedFiles) {
        try {
          await unlink(file.path);
          deletedSize += file.size;
          
          // Check if we've deleted enough
          const currentUsage = await this.getStorageUsage();
          if (currentUsage <= targetSize) {
            break;
          }
        } catch (error) {
          logger.error(`Error deleting file ${file.path}:`, error);
        }
      }
      
      logger.info(`Freed ${(deletedSize / (1024 * 1024)).toFixed(2)} MB of storage`);
      
    } catch (error) {
      logger.error('Error during storage cleanup:', error);
      throw new Error('Failed to clean up old files');
    }
  }

  /**
   * Gets a path for a new file, ensuring the directory exists
   */
  public static async getFilePath(
    subfolder: string,
    filename: string,
    createDir: boolean = true
  ): Promise<string> {
    try {
      const dirPath = path.join(this.STORAGE_DIR, subfolder);
      
      if (createDir) {
        await this.ensureDirectoryExists(dirPath);
      }
      
      return path.join(dirPath, filename);
    } catch (error) {
      logger.error('Error getting file path:', { subfolder, filename, error });
      throw new Error('Failed to get file path');
    }
  }

  /**
   * Deletes a file
   */
  public static async deleteFile(filePath: string): Promise<void> {
    try {
      await unlink(filePath);
    } catch (error) {
      if (error.code !== 'ENOENT') { // Ignore "file not found" errors
        logger.error(`Error deleting file ${filePath}:`, error);
        throw new Error('Failed to delete file');
      }
    }
  }

  /**
   * Checks if a file exists
   */
  public static async fileExists(filePath: string): Promise<boolean> {
    try {
      await access(filePath);
      return true;
    } catch (error) {
      return false;
    }
  }

  /**
   * Gets the size of a file in bytes
   */
  public static async getFileSize(filePath: string): Promise<number> {
    try {
      const stats = await stat(filePath);
      return stats.size;
    } catch (error) {
      logger.error(`Error getting file size for ${filePath}:`, error);
      throw new Error('Failed to get file size');
    }
  }
}

// Initialize storage on startup
StorageService.initialize().catch(error => {
  logger.error('Failed to initialize storage service:', error);
  process.exit(1);
});
