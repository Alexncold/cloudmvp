import { google, drive_v3 } from 'googleapis';
import { OAuth2Client } from 'google-auth-library';
import { promisify } from 'util';
import * as fs from 'fs';
import * as path from 'path';
import { logger } from '../utils/logger';
import { StorageService } from './storage.service';
import { EncryptionService } from './encryption.service';
import { EventEmitter } from 'events';
import { v4 as uuidv4 } from 'uuid';
import { createHash } from 'crypto';

const readFile = promisify(fs.readFile);

// Types for upload queue persistence
interface StoredUploadItem {
  id: string;
  filePath: string;
  fileName: string;
  mimeType: string;
  folderId?: string;
  status: 'pending' | 'processing' | 'completed' | 'failed';
  retryCount: number;
  createdAt: string;
  lastAttemptAt?: string;
  error?: string;
  metadata?: Record<string, any>;
  isEncrypted?: boolean;
  encryptionKeyId?: string;
  fileHash?: string;
  sizeBytes: number;
}

export interface UploadOptions {
  filePath: string;
  folderId?: string;
  fileName?: string;
  mimeType?: string;
  maxRetries?: number;
  initialDelayMs?: number;
  maxDelayMs?: number;
  deleteAfterUpload?: boolean;
  metadata?: Record<string, any>;
  encrypt?: boolean;
  encryptionKeyId?: string;
}

export interface UploadMetrics {
  totalUploads: number;
  successfulUploads: number;
  failedUploads: number;
  totalBytesUploaded: number;
  averageUploadTime: number;
  currentQueueSize: number;
  activeUploads: number;
  lastUploadTime?: Date;
  errorRate: number;
  retryCount: number;
}

interface CircuitBreakerState {
  isOpen: boolean;
  lastFailure: number;
  failureCount: number;
  nextAttempt: number;
}

const QUEUE_FILE_PATH = path.join(process.cwd(), 'data', 'upload-queue.json');
const METRICS_FILE_PATH = path.join(process.cwd(), 'data', 'upload-metrics.json');

export interface UploadResult {
  success: boolean;
  fileId?: string;
  webViewLink?: string;
  error?: string;
  retries: number;
  filePath: string;
  sizeBytes: number;
}

// Event types for the UploadService
declare interface UploadService {
  // Event listeners
  on(event: 'uploadSuccess', listener: (result: UploadResult) => void): this;
  on(event: 'uploadFailed', listener: (result: UploadResult) => void): this;
  on(event: 'uploadRetry', listener: (data: { 
    filePath: string; 
    retryCount: number; 
    maxRetries: number; 
    nextRetryInMs: number;
    error: string;
    sizeBytes: number;
  }) => void): this;
  on(event: 'uploadError', listener: (error: Error) => void): this;
  on(event: 'uploadProgress', listener: (data: {
    filePath: string;
    bytesRead: number;
    totalBytes: number;
    progress: number;
  }) => void): this;
  on(event: 'circuitBreakerOpened', listener: (data: { 
    failureCount: number; 
    nextAttempt: Date 
  }) => void): this;
  on(event: 'circuitBreakerReset', listener: () => void): this;
  
  // Event emitters
  emit(event: 'uploadSuccess', result: UploadResult): boolean;
  emit(event: 'uploadFailed', result: UploadResult): boolean;
  emit(event: 'uploadRetry', data: { 
    filePath: string; 
    retryCount: number; 
    maxRetries: number; 
    nextRetryInMs: number;
    error: string;
    sizeBytes: number;
  }): boolean;
  emit(event: 'uploadError', error: Error): boolean;
  emit(event: 'uploadProgress', data: {
    filePath: string;
    bytesRead: number;
    totalBytes: number;
    progress: number;
  }): boolean;
  emit(event: 'circuitBreakerOpened', data: { 
    failureCount: number; 
    nextAttempt: Date 
  }): boolean;
  emit(event: 'circuitBreakerReset'): boolean;
}

class UploadService extends EventEmitter {
  private static instance: UploadService;
  private drive: drive_v3.Drive | null = null;
  private uploadQueue: StoredUploadItem[] = [];
  private activeUploads = new Set<string>();
  private activeUploadsCount = 0;
  private isProcessing = false;
  private metrics: UploadMetrics;
  private circuitBreaker: CircuitBreakerState;
  private metricsSaveInterval: NodeJS.Timeout | null = null;
  private queueSaveInterval: NodeJS.Timeout | null = null;

  private readonly DEFAULT_CONFIG = {
    MAX_RETRIES: 5,
    INITIAL_DELAY_MS: 1000, // 1 second
    MAX_DELAY_MS: 300000,   // 5 minutes
    MAX_CONCURRENT_UPLOADS: 3,
    CHUNK_SIZE: 5 * 1024 * 1024, // 5MB chunks for resumable uploads
    QUEUE_SAVE_INTERVAL: 5000, // Save queue every 5 seconds
    METRICS_SAVE_INTERVAL: 60000, // Save metrics every minute
    CIRCUIT_BREAKER_THRESHOLD: 5, // Number of failures before opening circuit
    CIRCUIT_BREAKER_TIMEOUT: 30000, // 30 seconds circuit breaker timeout
  };

  private constructor() {
    super();
    this.drive = null;
    this.circuitBreaker = {
      isOpen: false,
      lastFailure: 0,
      failureCount: 0,
      nextAttempt: 0,
    };
    this.metrics = this.initializeMetrics();
    this.initialize();
  }

  private async initialize() {
    await this.ensureDataDirectory();
    await this.loadQueue();
    await this.loadMetrics();
    await this.initializeDrive();
    
    // Set up periodic tasks
    this.queueSaveInterval = setInterval(
      () => this.saveQueue().catch(error => 
        logger.error('Failed to save upload queue:', error)
      ),
      this.DEFAULT_CONFIG.QUEUE_SAVE_INTERVAL
    );

    this.metricsSaveInterval = setInterval(
      () => this.saveMetrics().catch(error =>
        logger.error('Failed to save upload metrics:', error)
      ),
      this.DEFAULT_CONFIG.METRICS_SAVE_INTERVAL
    );

    // Process any pending uploads on startup
    this.processQueue().catch(error =>
      logger.error('Error processing upload queue on startup:', error)
    );
  }

  private async ensureDataDirectory() {
    const dataDir = path.dirname(QUEUE_FILE_PATH);
    if (!fs.existsSync(dataDir)) {
      await fs.promises.mkdir(dataDir, { recursive: true });
    }
  }

  public static getInstance(): UploadService {
    if (!UploadService.instance) {
      UploadService.instance = new UploadService();
    }
    return UploadService.instance;
  }

  private async loadQueue() {
    try {
      if (fs.existsSync(QUEUE_FILE_PATH)) {
        const data = await fs.promises.readFile(QUEUE_FILE_PATH, 'utf-8');
        this.uploadQueue = JSON.parse(data).filter((item: StoredUploadItem) => 
          item.status === 'pending' || item.status === 'processing'
        );
        logger.info(`Loaded ${this.uploadQueue.length} pending uploads from queue`);
      }
    } catch (error) {
      logger.error('Error loading upload queue:', error);
      this.uploadQueue = [];
    }
  }

  private async saveQueue(): Promise<void> {
    try {
      const data = JSON.stringify(this.uploadQueue, null, 2);
      await fs.promises.writeFile(QUEUE_FILE_PATH, data, 'utf-8');
    } catch (error) {
      logger.error('Error saving upload queue:', error);
      throw error;
    }
  }

  private initializeMetrics(): UploadMetrics {
    return {
      totalUploads: 0,
      successfulUploads: 0,
      failedUploads: 0,
      totalBytesUploaded: 0,
      averageUploadTime: 0,
      currentQueueSize: 0,
      activeUploads: 0,
      errorRate: 0,
      retryCount: 0,
    };
  }

  private async loadMetrics() {
    try {
      if (fs.existsSync(METRICS_FILE_PATH)) {
        const data = await fs.promises.readFile(METRICS_FILE_PATH, 'utf-8');
        this.metrics = { ...this.initializeMetrics(), ...JSON.parse(data) };
      }
    } catch (error) {
      logger.error('Error loading upload metrics:', error);
      this.metrics = this.initializeMetrics();
    }
  }

  private async saveMetrics(): Promise<void> {
    try {
      this.metrics.currentQueueSize = this.uploadQueue.length;
      this.metrics.activeUploads = this.activeUploads.size;
      
      const data = JSON.stringify(this.metrics, null, 2);
      await fs.promises.writeFile(METRICS_FILE_PATH, data, 'utf-8');
    } catch (error) {
      logger.error('Error saving upload metrics:', error);
      throw error;
    }
  }

  private async initializeDrive() {
    try {
      const auth = await this.authenticate();
      this.drive = google.drive({ version: 'v3', auth });
      logger.info('Google Drive client initialized');
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      logger.error('Failed to initialize Google Drive client:', errorMessage);
      // Set drive to null to indicate initialization failure
      this.drive = null;
      throw new Error(`Failed to initialize Google Drive client: ${errorMessage}`);
    }
  }

  private async authenticate() {
    const credentials = JSON.parse(process.env.GOOGLE_DRIVE_CREDENTIALS || '{}');
    const auth = new OAuth2Client({
      clientId: credentials.client_id,
      clientSecret: credentials.client_secret,
      redirectUri: credentials.redirect_uris?.[0],
    });

    // Set credentials if refresh token is available
    if (process.env.GOOGLE_DRIVE_REFRESH_TOKEN) {
      auth.setCredentials({
        refresh_token: process.env.GOOGLE_DRIVE_REFRESH_TOKEN,
      });
    }

    return auth;
  }

  /**
   * Uploads a file to Google Drive with retry logic and encryption support
   * @param options Upload options including file path, encryption settings, etc.
   * @returns Promise resolving to upload result
   */
  public async uploadFile(options: UploadOptions): Promise<UploadResult> {
    const {
      filePath,
      fileName = path.basename(filePath),
      folderId,
      mimeType = 'application/octet-stream',
      maxRetries = this.DEFAULT_CONFIG.MAX_RETRIES,
      initialDelayMs = this.DEFAULT_CONFIG.INITIAL_DELAY_MS,
      maxDelayMs = this.DEFAULT_CONFIG.MAX_DELAY_MS,
      deleteAfterUpload = true,
      encrypt = false,
      encryptionKeyId,
      metadata = {}
    } = options;
    
    if (encrypt && !encryptionKeyId) {
      throw new Error('encryptionKeyId is required when encrypt is true');
    }

    const stats = await fs.promises.stat(filePath);
    const fileSize = stats.size;

    const uploadItem: StoredUploadItem = {
      id: uuidv4(),
      filePath,
      fileName,
      mimeType,
      folderId,
      status: 'pending',
      retryCount: 0,
      createdAt: new Date().toISOString(),
      sizeBytes: fileSize,
      isEncrypted: encrypt,
      encryptionKeyId: encrypt ? encryptionKeyId : undefined,
      metadata: {
        ...metadata,
        maxRetries,
        initialDelayMs,
        maxDelayMs,
        deleteAfterUpload,
      },
    };

    // Add to queue and process
    this.uploadQueue.push(uploadItem);
    await this.saveQueue();
    
    // Start processing the queue if not already running
    this.processQueue().catch((error: Error) => 
      logger.error('Error processing upload queue:', error)
    );
    
    // Wait for the upload to complete or fail
    return new Promise<UploadResult>((resolve) => {
      const onComplete = (result: UploadResult) => {
        if (result.filePath === filePath) {
          this.off('uploadSuccess', onSuccess);
          this.off('uploadFailed', onFail);
          resolve(result);
        }
      };
      
      const onSuccess = (result: UploadResult) => onComplete(result);
      const onFail = (result: UploadResult) => onComplete(result);
      
      this.on('uploadSuccess', onSuccess);
      this.on('uploadFailed', onFail);
    });
  }

  /**
   * Internal method to handle the actual upload to Google Drive
   */
  /**
   * Uploads a file to Google Drive
   * @param fileItem The file item to upload
   * @returns Object containing fileId and webViewLink
   */
  private async uploadFileToDrive(fileItem: StoredUploadItem & { tempFilePath?: string }): Promise<{ fileId: string; webViewLink: string }> {
    if (!this.drive) {
      throw new Error('Google Drive client is not initialized');
    }

    const { filePath, fileName, mimeType, folderId } = fileItem;
    
    try {
      // Create a readable stream for the file
      const fileStream = fs.createReadStream(filePath);
      
      // Set up the file metadata
      const fileMetadata: drive_v3.Params$Resource$Files$Create = {
        requestBody: {
          name: fileName,
          mimeType,
          parents: folderId ? [folderId] : undefined,
        },
        media: {
          mimeType: mimeType || 'application/octet-stream',
          body: fileStream,
        },
        fields: 'id,webViewLink',
      };

      // Upload the file to Google Drive
      const response = await this.drive.files.create(fileMetadata, {
        onUploadProgress: (evt) => {
          // Emit upload progress event if needed
          this.emit('uploadProgress', {
            filePath,
            bytesRead: evt.bytesRead,
            totalBytes: fileItem.sizeBytes,
            progress: evt.bytesRead / fileItem.sizeBytes,
          });
        },
      });
      
      if (!response.data.id) {
        throw new Error('No file ID returned from Google Drive');
      }

      // Clean up the temporary file if it was created for decryption
      if (fileItem.tempFilePath) {
        try {
          await fs.promises.unlink(fileItem.tempFilePath);
          logger.info(`Cleaned up temporary file: ${fileItem.tempFilePath}`);
        } catch (cleanupError) {
          logger.error(`Failed to clean up temporary file ${fileItem.tempFilePath}:`, cleanupError);
        }
      }

      // Update metrics
      this.metrics.totalBytesUploaded += fileItem.sizeBytes;
      this.metrics.successfulUploads++;
      
      return {
        fileId: response.data.id,
        webViewLink: response.data.webViewLink || ''
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      logger.error(`Failed to upload file ${filePath} to Google Drive:`, errorMessage);
      
      // Record the failure for circuit breaker
      this.recordFailure();
      
      // Rethrow the error for the caller to handle
      throw new Error(`Upload failed: ${errorMessage}`);
    }
  }

/**
 * Processes the upload queue with concurrency control
 * Handles multiple uploads in parallel up to the configured maximum
 */
private async processQueue(): Promise<void> {
  if (this.isProcessing || this.uploadQueue.length === 0) {
    return;
  }

  this.isProcessing = true;

  try {
    // Process up to MAX_CONCURRENT_UPLOADS items at once
    const processingPromises: Promise<void>[] = [];
    
    for (let i = 0; i < Math.min(this.uploadQueue.length, this.DEFAULT_CONFIG.MAX_CONCURRENT_UPLOADS); i++) {
      const item = this.uploadQueue[i];
      if (item.status === 'pending') {
        item.status = 'processing';
        processingPromises.push(this.processUploadItem(item));
      }
    }

    await Promise.all(processingPromises);
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    logger.error('Error processing upload queue:', errorMessage);
  } finally {
    this.isProcessing = false;
    
    // If there are still pending items, schedule another processing run
    if (this.uploadQueue.some(item => item.status === 'pending')) {
      setImmediate(() => this.processQueue().catch(err => 
        logger.error('Error in subsequent queue processing:', err)
      ));
    }
  }
}

/**
 * Processes a single upload item from the queue
 * Handles decryption if needed, uploads to Google Drive, and cleans up
 */
private async processUploadItem(item: StoredUploadItem): Promise<void> {
  let tempFilePath: string | null = null;
  let shouldCleanupTempFile = false;
  
  try {
    // Update metrics
    this.metrics.activeUploads++;
    
    logger.info(`Decrypting file ${item.filePath} for upload...`);
    if (!item.encryptionKeyId) {
      throw new Error('Encryption key ID is required for decryption');
    }
    
    // Upload the file to Google Drive
    const uploadPath = tempFilePath || item.filePath;
    const result = await this.uploadFileToDrive({
      ...item,
      filePath: uploadPath,
      tempFilePath: shouldCleanupTempFile && tempFilePath ? tempFilePath : undefined
    } as StoredUploadItem & { tempFilePath?: string });
    
    // Update item status
    item.status = 'completed';
    item.lastAttemptAt = new Date().toISOString();
    
    // Emit success event
    this.emit('uploadSuccess', {
      ...result,
      success: true,
      retries: item.retryCount,
      filePath: item.filePath,
      sizeBytes: item.sizeBytes,
    });
    
    // Remove from queue
    this.uploadQueue = this.uploadQueue.filter(i => i.id !== item.id);
    
    // Update metrics
    this.metrics.successfulUploads++;
    this.metrics.totalUploads++;
    this.metrics.totalBytesUploaded += item.sizeBytes;
    
  } catch (error) {
    await this.handleUploadError(item, error);
  } finally {
    // Clean up temporary decrypted file if it exists
    if (shouldCleanupTempFile && tempFilePath) {
      try {
        await fs.promises.unlink(tempFilePath);
      } catch (error) {
        logger.error(`Failed to clean up temporary file ${tempFilePath}:`, error);
      }
    }
    
    // Update metrics
    this.metrics.activeUploads = Math.max(0, this.metrics.activeUploads - 1);
    
    // Save updated queue and metrics
    await Promise.all([
      this.saveQueue(),
      this.saveMetrics()
    ]);
  }
}

/**
 * Handles upload errors and implements retry logic with exponential backoff
 * @param item The upload item that failed
 * @param error The error that occurred
 */
  private keepFailedItems = false; // Class property to control whether to keep failed items in the queue

  private async handleUploadError(item: StoredUploadItem, error: unknown): Promise<void> {
    const errorMessage = error instanceof Error ? error.message : String(error);
    
    item.retryCount++;
    item.lastAttemptAt = new Date().toISOString();
    item.error = errorMessage;
    
    // Check if we should retry
    const maxRetries = item.metadata?.maxRetries || this.DEFAULT_CONFIG.MAX_RETRIES;
    
    if (item.retryCount <= maxRetries) {
      // Calculate delay with exponential backoff and jitter
      const initialDelay = item.metadata?.initialDelayMs || this.DEFAULT_CONFIG.INITIAL_DELAY_MS;
      const maxDelay = item.metadata?.maxDelayMs || this.DEFAULT_CONFIG.MAX_DELAY_MS;
      const delay = Math.min(initialDelay * Math.pow(2, item.retryCount - 1), maxDelay);
      const jitter = Math.random() * delay * 0.5; // Add up to 50% jitter
      const backoffTime = Math.floor(delay + jitter);
      
      // Update item status
      item.status = 'pending';
      
      // Emit retry event
      this.emit('uploadRetry', {
        filePath: item.filePath,
        retryCount: item.retryCount,
        maxRetries,
        nextRetryInMs: backoffTime,
        error: errorMessage,
        sizeBytes: item.sizeBytes,
      });
      
      // Schedule retry
      setTimeout(() => {
        this.processQueue().catch(err => 
          logger.error('Error processing queue after retry:', err)
        );
      }, backoffTime);
      
    } else {
      // Max retries reached, mark as failed
      item.status = 'failed';
      
      // Emit failure event
      this.emit('uploadFailed', {
        success: false,
        error: `Upload failed after ${item.retryCount} attempts: ${errorMessage}`,
        retries: item.retryCount,
        filePath: item.filePath,
        sizeBytes: item.sizeBytes,
      });
      
      // Update metrics
      this.metrics.failedUploads++;
      this.metrics.totalUploads++;
      
      // Remove from queue if we're not keeping failed items
      if (!this.keepFailedItems) {
        this.uploadQueue = this.uploadQueue.filter(i => i.id !== item.id);
      }
    }
    
    // Log the error
    logger.error(`Upload failed for ${item.filePath} (attempt ${item.retryCount}/${maxRetries}):`, error);
  }

  /**
   * Records a failure and updates the circuit breaker state
   * Opens the circuit if failure threshold is reached
   */
  private recordFailure(): void {
    this.circuitBreaker.failureCount++;
    this.circuitBreaker.lastFailure = Date.now();
    
    if (this.circuitBreaker.failureCount >= this.DEFAULT_CONFIG.CIRCUIT_BREAKER_THRESHOLD) {
      this.circuitBreaker.isOpen = true;
      this.circuitBreaker.nextAttempt = Date.now() + this.DEFAULT_CONFIG.CIRCUIT_BREAKER_TIMEOUT;
      logger.warn(`Circuit breaker opened. Next attempt at ${new Date(this.circuitBreaker.nextAttempt).toISOString()}`);
      
      // Emit circuit breaker event
      this.emit('circuitBreakerOpened', {
        failureCount: this.circuitBreaker.failureCount,
        nextAttempt: new Date(this.circuitBreaker.nextAttempt)
      });
    }
  }

  /**
   * Resets the circuit breaker to its initial state
   * Called when operations start succeeding again
   */
  private resetCircuitBreaker(): void {
    logger.info('Resetting circuit breaker');
    this.circuitBreaker = {
      isOpen: false,
      failureCount: 0,
      lastFailure: 0,
      nextAttempt: 0,
    };
    
    // Emit circuit breaker reset event
    this.emit('circuitBreakerReset');
  }

  /**
   * Calculates a moving average for metrics
   * @param currentAverage The current average value
   * @param count The number of values in the average
   * @param newValue The new value to include in the average
   * @returns The new moving average
   */
  private calculateMovingAverage(currentAverage: number, count: number, newValue: number): number {
    if (count <= 0) return newValue;
    return (currentAverage * (count - 1) + newValue) / count;
  }
}

export const uploadService = UploadService.getInstance();
