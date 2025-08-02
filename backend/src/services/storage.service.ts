import * as fs from 'fs';
import * as path from 'path';
import { EventEmitter } from 'events';
import { promisify } from 'util';
import { logger } from '../utils/logger';

const readdir = promisify(fs.readdir);
const stat = promisify(fs.stat);
const unlink = promisify(fs.unlink);
const mkdir = promisify(fs.mkdir);
const access = promisify(fs.access);
const readFile = promisify(fs.readFile);
const writeFile = promisify(fs.writeFile);

interface FileInfo {
  path: string;
  size: number;
  createdAt: Date;
  lastAccessed: Date;
  metadata?: Record<string, any>;
}

export interface StorageMetrics {
  totalSpace: number;        // in bytes
  usedSpace: number;         // in bytes
  freeSpace: number;         // in bytes
  usagePercentage: number;   // 0-100
  filesCount: number;
  lastCleanup: Date | null;
  nextCleanup: Date | null;
}

export interface RetentionPolicy {
  maxAgeDays?: number;       // Delete files older than X days
  maxUsagePercentage?: number; // Start cleanup when usage exceeds this percentage
  minFreeSpaceGB?: number;   // Ensure at least X GB free space
  priority?: 'oldest' | 'largest' | 'oldest-large';
}

export interface CameraStorageInfo {
  cameraId: string;
  totalSize: number;
  fileCount: number;
  lastRecording: Date | null;
  oldestRecording: Date | null;
}

export class StorageService extends EventEmitter {
  private static instance: StorageService;
  
  private readonly STORAGE_DIR: string;
  private readonly MAX_STORAGE_BYTES: number;
  private readonly CLEANUP_THRESHOLD: number = 0.8; // 80% usage triggers cleanup
  private readonly DEFAULT_RETENTION: RetentionPolicy = {
    maxAgeDays: 7,
    maxUsagePercentage: 80,
    minFreeSpaceGB: 5,
    priority: 'oldest-large'
  };
  
  private cleanupInterval: NodeJS.Timeout | null = null;
  private metrics: StorageMetrics = {
    totalSpace: 0,
    usedSpace: 0,
    freeSpace: 0,
    usagePercentage: 0,
    filesCount: 0,
    lastCleanup: null,
    nextCleanup: null
  };
  
  private constructor() {
    super();
    this.STORAGE_DIR = process.env.STORAGE_DIR || './storage/videos';
    this.MAX_STORAGE_BYTES = parseInt(process.env.MAX_STORAGE_MB || '10240') * 1024 * 1024; // Default 10GB
    
    // Set up periodic cleanup check (every hour)
    this.setupCleanupInterval(60 * 60 * 1000);
  }
  
  public static getInstance(): StorageService {
    if (!StorageService.instance) {
      StorageService.instance = new StorageService();
    }
    return StorageService.instance;
  }

  /**
   * Initializes the storage service
   */
  public async initialize(): Promise<void> {
    try {
      await this.ensureDirectoryExists(this.STORAGE_DIR);
      await this.updateMetrics();
      
      logger.info(`Storage service initialized at ${path.resolve(this.STORAGE_DIR)}`);
      logger.info(`Storage capacity: ${(this.MAX_STORAGE_BYTES / (1024 * 1024)).toFixed(2)} MB`);
      logger.info(`Current usage: ${(this.metrics.usedSpace / (1024 * 1024)).toFixed(2)} MB (${this.metrics.usagePercentage.toFixed(2)}%)`);
      
      // Perform initial cleanup if needed
      if (this.shouldRunCleanup()) {
        await this.cleanupOldFiles();
      }
    } catch (error) {
      logger.error('Failed to initialize storage service:', error);
      throw new Error('Failed to initialize storage service');
    }
  }

  /**
   * Sets up periodic cleanup checks
   */
  private setupCleanupInterval(intervalMs: number): void {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
    }
    
    this.cleanupInterval = setInterval(async () => {
      try {
        if (this.shouldRunCleanup()) {
          await this.cleanupOldFiles();
        }
      } catch (error) {
        logger.error('Error during scheduled cleanup:', error);
      }
    }, intervalMs);
  }

  /**
   * Determines if cleanup should run based on current metrics
   */
  private shouldRunCleanup(): boolean {
    const usagePercent = (this.metrics.usedSpace / this.MAX_STORAGE_BYTES) * 100;
    const freeSpaceGB = (this.MAX_STORAGE_BYTES - this.metrics.usedSpace) / (1024 * 1024 * 1024);
    
    return (
      usagePercent > (this.DEFAULT_RETENTION.maxUsagePercentage || 80) ||
      freeSpaceGB < (this.DEFAULT_RETENTION.minFreeSpaceGB || 5)
    );
  }

  /**
   * Ensures a directory exists, creates it if it doesn't
   */
  private async ensureDirectoryExists(dirPath: string): Promise<void> {
    try {
      await access(dirPath);
    } catch (error: any) {
      if (error.code === 'ENOENT') {
        // Directory doesn't exist, create it
        await mkdir(dirPath, { recursive: true });
      } else {
        throw error;
      }
    }
  }

  /**
   * Updates storage metrics
   */
  public async updateMetrics(): Promise<StorageMetrics> {
    try {
      const files = await this.getAllFiles();
      const usedSpace = files.reduce((total, file) => total + file.size, 0);
      const freeSpace = Math.max(0, this.MAX_STORAGE_BYTES - usedSpace);
      const usagePercentage = (usedSpace / this.MAX_STORAGE_BYTES) * 100;
      
      this.metrics = {
        totalSpace: this.MAX_STORAGE_BYTES,
        usedSpace,
        freeSpace,
        usagePercentage,
        filesCount: files.length,
        lastCleanup: this.metrics.lastCleanup,
        nextCleanup: this.calculateNextCleanupTime()
      };
      
      this.emit('metricsUpdated', this.metrics);
      return this.metrics;
    } catch (error) {
      logger.error('Error updating storage metrics:', error);
      throw new Error('Failed to update storage metrics');
    }
  }
  
  /**
   * Gets current storage metrics
   */
  public getMetrics(): StorageMetrics {
    return { ...this.metrics };
  }
  
  /**
   * Calculates when the next cleanup should occur
   */
  private calculateNextCleanupTime(): Date | null {
    if (!this.metrics.lastCleanup) return null;
    
    // Schedule next cleanup for 24 hours after last cleanup
    const next = new Date(this.metrics.lastCleanup);
    next.setHours(next.getHours() + 24);
    return next;
  }

  /**
   * Gets all files in a directory recursively with metadata
   */
  public async getAllFiles(dir: string = this.STORAGE_DIR): Promise<FileInfo[]> {
    const files: FileInfo[] = [];
    
    try {
      const entries = await readdir(dir, { withFileTypes: true });
      
      for (const entry of entries) {
        const fullPath = path.join(dir, entry.name);
        
        try {
          if (entry.isDirectory()) {
            // Recursively get files in subdirectories
            const subFiles = await this.getAllFiles(fullPath);
            files.push(...subFiles);
          } else if (entry.isFile()) {
            // Get file stats and parse metadata if available
            const stats = await stat(fullPath);
            const fileInfo: FileInfo = {
              path: fullPath,
              size: stats.size,
              createdAt: stats.birthtime || stats.ctime,
              lastAccessed: stats.atime
            };
            
            // Skip metadata files in the main file list
            if (fullPath.endsWith('.meta')) {
              continue;
            }
            
            // Try to load metadata file if it exists
            const metadataPath = `${fullPath}.meta`;
            try {
              if (await this.fileExists(metadataPath)) {
                const metadataContent = await readFile(metadataPath, 'utf-8');
                fileInfo.metadata = JSON.parse(metadataContent);
              }
            } catch (error) {
              logger.warn(`Failed to load metadata for ${fullPath}:`, error);
            }
            
            files.push(fileInfo);
          }
        } catch (error: any) {
          if (error.code !== 'ENOENT') { // Skip files that were deleted during processing
            logger.error(`Error processing ${fullPath}:`, error);
          }
        }
      }
    } catch (error: any) {
      if (error.code !== 'ENOENT') { // Ignore "directory doesn't exist" errors
        logger.error(`Error reading directory ${dir}:`, error);
        throw error;
      }
    }
    
    return files;
  }

  /**
   * Cleans up old files based on retention policy
   */
  public async cleanupOldFiles(policy: RetentionPolicy = this.DEFAULT_RETENTION): Promise<void> {
    try {
      logger.info('Starting storage cleanup...');
      
      // Get all files with metadata
      const allFiles = await this.getAllFiles();
      if (allFiles.length === 0) {
        logger.info('No files to clean up');
        return;
      }
      
      // Sort files based on priority
      const sortedFiles = this.sortFilesForCleanup(allFiles, policy);
      
      // Calculate space to free
      const targetFreeSpace = policy.minFreeSpaceGB ? 
        policy.minFreeSpaceGB * 1024 * 1024 * 1024 : 
        this.MAX_STORAGE_BYTES * 0.2; // Default to 20% free space
      
      const currentFreeSpace = this.metrics.freeSpace;
      let spaceToFree = Math.max(0, targetFreeSpace - currentFreeSpace);
      
      if (spaceToFree <= 0 && !policy.maxAgeDays) {
        logger.info('No cleanup needed - sufficient free space available');
        return;
      }
      
      // Delete files until we meet our targets
      let deletedCount = 0;
      let deletedSize = 0;
      const now = new Date();
      const maxAgeMs = policy.maxAgeDays ? policy.maxAgeDays * 24 * 60 * 60 * 1000 : Infinity;
      
      for (const file of sortedFiles) {
        try {
          // Check if file is too old
          const fileAge = now.getTime() - file.createdAt.getTime();
          const isTooOld = fileAge > maxAgeMs;
          
          // Skip if file doesn't meet any cleanup criteria
          if (!isTooOld && spaceToFree <= 0) {
            continue;
          }
          
          // Delete the file and its metadata
          await this.deleteFile(file.path);
          
          // Update metrics
          deletedCount++;
          deletedSize += file.size;
          spaceToFree -= file.size;
          
          // Stop if we've freed enough space
          if (spaceToFree <= 0 && !isTooOld) {
            break;
          }
          
        } catch (error) {
          logger.error(`Error cleaning up file ${file.path}:`, error);
        }
      }
      
      // Update metrics
      this.metrics.lastCleanup = new Date();
      this.metrics.nextCleanup = this.calculateNextCleanupTime();
      
      logger.info(`Storage cleanup completed: Deleted ${deletedCount} files, freed ${(deletedSize / (1024 * 1024)).toFixed(2)} MB`);
      this.emit('cleanupCompleted', { deletedCount, deletedSize });
      
    } catch (error) {
      logger.error('Error during storage cleanup:', error);
      this.emit('cleanupError', error);
      throw new Error('Failed to clean up old files');
    } finally {
      // Always update metrics after cleanup
      await this.updateMetrics();
    }
  }
  
  /**
   * Sorts files based on cleanup priority
   */
  private sortFilesForCleanup(files: FileInfo[], policy: RetentionPolicy): FileInfo[] {
    const priority = policy.priority || 'oldest-large';
    
    switch (priority) {
      case 'oldest':
        return [...files].sort((a, b) => a.createdAt.getTime() - b.createdAt.getTime());
        
      case 'largest':
        return [...files].sort((a, b) => b.size - a.size);
        
      case 'oldest-large':
      default:
        // Sort by oldest first, then by largest within same age groups
        return [...files].sort((a, b) => {
          const ageDiff = a.createdAt.getTime() - b.createdAt.getTime();
          if (ageDiff !== 0) return ageDiff;
          return b.size - a.size;
        });
    }
  }

  /**
   * Gets a path for a new recording file with metadata
   */
  public async getRecordingPath(
    cameraId: string,
    segmentNumber: number,
    extension: string = 'mp4',
    metadata: Record<string, any> = {}
  ): Promise<{ filePath: string; metadataPath: string }> {
    try {
      // Create directory structure: /storage/videos/{cameraId}/YYYY/MM/DD
      const now = new Date();
      const datePath = `${now.getFullYear()}/${String(now.getMonth() + 1).padStart(2, '0')}/${String(now.getDate()).padStart(2, '0')}`;
      const dirPath = path.join(this.STORAGE_DIR, cameraId, datePath);
      
      // Ensure directory exists
      await this.ensureDirectoryExists(dirPath);
      
      // Generate filename with timestamp and segment number
      const timestamp = now.toISOString().replace(/[:.]/g, '-');
      const filename = `${cameraId}_${timestamp}_seg${String(segmentNumber).padStart(5, '0')}.${extension}`;
      const filePath = path.join(dirPath, filename);
      
      // Prepare metadata
      const fileMetadata = {
        cameraId,
        segmentNumber,
        createdAt: now.toISOString(),
        ...metadata
      };
      
      // Save metadata to a separate file
      const metadataPath = `${filePath}.meta`;
      await writeFile(metadataPath, JSON.stringify(fileMetadata, null, 2), 'utf-8');
      
      // Update metrics
      await this.updateMetrics();
      
      return { filePath, metadataPath };
    } catch (error) {
      logger.error('Error getting recording path:', { cameraId, segmentNumber, error });
      throw new Error('Failed to get recording path');
    }
  }

  /**
   * Deletes a file and its metadata
   */
  public async deleteFile(filePath: string): Promise<void> {
    try {
      // Delete the main file
      await unlink(filePath).catch(error => {
        if (error.code !== 'ENOENT') throw error;
      });
      
      // Try to delete metadata file if it exists
      const metadataPath = `${filePath}.meta`;
      await unlink(metadataPath).catch(error => {
        if (error.code !== 'ENOENT') throw error;
      });
      
      // Update metrics
      await this.updateMetrics();
      
    } catch (error: any) {
      if (error.code !== 'ENOENT') { // Ignore "file not found" errors
        logger.error(`Error deleting file ${filePath}:`, error);
        throw new Error('Failed to delete file');
      }
    }
  }

  /**
   * Checks if a file exists
   */
  public async fileExists(filePath: string): Promise<boolean> {
    try {
      await access(filePath);
      return true;
    } catch (error) {
      return false;
    }
  }
  
  /**
   * Gets storage information for a specific camera
   */
  public async getCameraStorageInfo(cameraId: string): Promise<CameraStorageInfo> {
    try {
      const cameraDir = path.join(this.STORAGE_DIR, cameraId);
      const allFiles = await this.getAllFiles(cameraDir);
      
      if (allFiles.length === 0) {
        return {
          cameraId,
          totalSize: 0,
          fileCount: 0,
          lastRecording: null,
          oldestRecording: null
        };
      }
      
      const sortedByDate = [...allFiles].sort((a, b) => 
        a.createdAt.getTime() - b.createdAt.getTime()
      );
      
      return {
        cameraId,
        totalSize: allFiles.reduce((sum, file) => sum + file.size, 0),
        fileCount: allFiles.length,
        oldestRecording: sortedByDate[0]?.createdAt || null,
        lastRecording: sortedByDate[sortedByDate.length - 1]?.createdAt || null
      };
    } catch (error) {
      logger.error(`Error getting storage info for camera ${cameraId}:`, error);
      throw new Error(`Failed to get storage info for camera ${cameraId}`);
    }
  }
  
  /**
   * Deletes all files for a specific camera
   */
  public async deleteCameraFiles(cameraId: string): Promise<{ deletedCount: number; deletedSize: number }> {
    try {
      const cameraDir = path.join(this.STORAGE_DIR, cameraId);
      const allFiles = await this.getAllFiles(cameraDir);
      
      let deletedCount = 0;
      let deletedSize = 0;
      
      for (const file of allFiles) {
        try {
          await this.deleteFile(file.path);
          deletedCount++;
          deletedSize += file.size;
        } catch (error) {
          logger.error(`Error deleting file ${file.path}:`, error);
        }
      }
      
      // Try to remove the camera directory if empty
      try {
        await fs.promises.rmdir(cameraDir);
      } catch (error) {
        // Directory not empty or already deleted, ignore
      }
      
      // Update metrics
      await this.updateMetrics();
      
      return { deletedCount, deletedSize };
    } catch (error) {
      logger.error(`Error deleting files for camera ${cameraId}:`, error);
      throw new Error(`Failed to delete files for camera ${cameraId}`);
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

// Export singleton instance
export const storageService = StorageService.getInstance();

// Initialize storage on startup
if (require.main === module) {
  storageService.initialize().catch(error => {
    logger.error('Failed to initialize storage service:', error);
    process.exit(1);
  });
}

