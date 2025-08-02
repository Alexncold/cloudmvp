import { Worker, Job } from 'bullmq';
import * as path from 'path';
import * as fs from 'fs';
import { logger } from '../utils/logger';
import { recordingService } from '../services/recording.service';
import { storageService } from '../services/storage.service';
import { uploadService, UploadResult } from '../services/upload.service';
import { EncryptionService } from '../services/encryption.service';
// TODO: Uncomment and implement these imports once the modules are available
// import { Camera } from '../../shared/types/camera';
// import { db } from '../database/db';

// Temporary types/interfaces - replace with actual imports when available
interface Camera {
  id: string;
  name: string;
  rtsp_url: string;  // Note: Using snake_case to match database schema
  is_active: boolean;
  encryption_enabled: boolean;
  username?: string;
  password?: string;
  drive_folder_id?: string;
  // Add other camera properties as needed
}

// Mock database implementation
const db = {
  camera: {
    findMany: async (): Promise<Camera[]> => [],
    findUnique: async (options: { where: { id: string } }): Promise<Camera | null> => ({
      id: options.where.id,
      name: 'Test Camera',
      rtsp_url: 'rtsp://example.com/stream',
      is_active: true,
      encryption_enabled: false
    } as Camera),
    update: async (options: { where: { id: string }, data: any }): Promise<Camera> => ({
      id: options.where.id,
      name: options.data.name || 'Test Camera',
      rtsp_url: options.data.rtsp_url || 'rtsp://example.com/stream',
      is_active: options.data.is_active !== undefined ? options.data.is_active : true,
      encryption_enabled: options.data.encryption_enabled || false
    } as Camera)
  },
  recording: {
    create: async (data: any) => ({
      id: 'rec-' + Math.random().toString(36).substr(2, 9),
      ...data
    }),
    update: async (options: { where: { id: string }, data: any }) => ({
      id: options.where.id,
      ...options.data
    }),
    // Add mock implementations for methods used in the code
    findUnique: async (options: { where: { id: string } }) => ({
      id: options.where.id,
      camera_id: 'cam-' + Math.random().toString(36).substr(2, 9),
      start_time: new Date(),
      end_time: null,
      status: 'recording',
      file_path: '/path/to/recording.mp4',
      size_bytes: 0
    })
  },
  // Add mock for oneOrNone and none if needed
  oneOrNone: async (query: string, params?: any) => null,
  none: async (query: string, params?: any) => {}
};
import { EventEmitter } from 'events';

interface RecordingJobData {
  cameraId: string;
  action: 'start' | 'stop' | 'restart' | 'upload';
  filePath?: string;
}

interface RecordingStatus {
  isRecording: boolean;
  lastError?: string;
  lastSegmentTime?: Date;
  segmentsRecorded: number;
  segmentsUploaded: number;
  segmentsFailed: number;
  bytesRecorded: number;
  lastUploadStatus?: string;
  // Add missing properties to match usage
  lastHeartbeat?: Date;
  reconnectAttempts?: number;
  currentSegment?: number;
  process?: any; // FFmpeg process reference
}

export class RecordingWorker extends EventEmitter {
  private worker: Worker<RecordingJobData, void, string>;
  private static instance: RecordingWorker;
  private recordings: Map<string, RecordingStatus> = new Map();
  private readonly STORAGE_CLEANUP_THRESHOLD = 0.8; // 80% usage
  private readonly SEGMENT_RETENTION_DAYS = parseInt(process.env.SEGMENT_RETENTION_DAYS || '7');

  private constructor() {
    super(); // Call the parent class (EventEmitter) constructor
    this.worker = new Worker<RecordingJobData>(
      'recording-queue',
      async (job: Job<RecordingJobData>) => {
        const { cameraId, action } = job.data;
        
        try {
          switch (action) {
            case 'start':
              await this.startRecording(cameraId);
              break;
            case 'stop':
              await this.stopRecording(cameraId);
              break;
            case 'restart':
              await this.stopRecording(cameraId);
              await new Promise(resolve => setTimeout(resolve, 1000)); // Small delay
              await this.startRecording(cameraId);
              break;
            default:
              throw new Error(`Unknown action: ${action}`);
          }
          
          logger.info(`Successfully processed ${action} for camera ${cameraId}`);
        } catch (error) {
          logger.error(`Error processing ${action} for camera ${cameraId}:`, error);
          throw error; // Will trigger the retry mechanism
        }
      },
      {
        connection: {
          host: process.env.REDIS_HOST || 'localhost',
          port: parseInt(process.env.REDIS_PORT || '6379'),
        },
        concurrency: 5, // Process up to 5 recordings in parallel
        removeOnComplete: { count: 1000 }, // Keep last 1000 completed jobs
        removeOnFail: { count: 5000 }, // Keep last 5000 failed jobs
      }
    );

    this.setupEventListeners();
  }

  public static getInstance(): RecordingWorker {
    if (!RecordingWorker.instance) {
      RecordingWorker.instance = new RecordingWorker();
    }
    return RecordingWorker.instance;
  }

  private setupEventListeners(): void {
    this.worker.on('completed', (job: Job) => {
      logger.debug(`Job ${job.id} completed for camera ${job.data.cameraId}`);
    });

    this.worker.on('failed', (job: Job | undefined, error: Error) => {
      const cameraId = job?.data?.cameraId || 'unknown';
      logger.error(`Job failed for camera ${cameraId}:`, error);
    });

    this.worker.on('error', (error: Error) => {
      logger.error('Worker error:', error);
    });

    // Listen for segment completion events
    recordingService.on('segmentComplete', this.handleSegmentComplete.bind(this));
  }

  private async startRecording(cameraId: string): Promise<void> {
    try {
      // Get camera details from the database
      const camera = await db.camera.findUnique({ where: { id: cameraId } });
      if (!camera) {
        throw new Error(`Camera with ID ${cameraId} not found`);
      }

      if (!camera.rtsp_url) {
        throw new Error(`No RTSP URL configured for camera ${cameraId}`);
      }

      // Create output directory for this camera
      const storageDir = process.env.STORAGE_DIR || './storage';
      const outputDir = path.join(storageDir, 'recordings', cameraId);
      await storageService.ensureDirectoryExists(outputDir);

      // Initialize recording status
      this.recordings.set(cameraId, {
        isRecording: true,
        segmentsRecorded: 0,
        segmentsUploaded: 0,
        segmentsFailed: 0,
        bytesRecorded: 0,
        lastSegmentTime: new Date()
      });

      // Check storage and clean up if needed
      await this.checkAndCleanStorage();

      // Start recording
      await recordingService.startRecording({
        cameraId,
        rtspUrl: camera.rtsp_url,
        segmentDuration: parseInt(process.env.SEGMENT_DURATION || '300'), // 5 minutes by default
        outputDir,
        enableEncryption: camera.encryption_enabled || false,
        username: camera.username || undefined,
        password: camera.password ? await this.decryptPassword(camera.password) : undefined,
        maxReconnectAttempts: 10,
        reconnectDelayMs: 5000,
        healthCheckIntervalMs: 30000
      });

      // Update recording status
      await this.updateRecordingStatus(
        cameraId,
        true,
        `Recording started at ${new Date().toISOString()}`,
        this.recordings.get(cameraId)
      );
      
      logger.info(`Started recording for camera ${cameraId}`, { outputDir });
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      logger.error(`Failed to start recording for camera ${cameraId}:`, error);
      await this.updateRecordingStatus(
        cameraId,
        false,
        `Failed to start recording: ${errorMessage}`,
        this.recordings.get(cameraId)
      );
      throw error;
    }
  }

  private async stopRecording(cameraId: string): Promise<void> {
    try {
      await recordingService.stopRecording(cameraId);
      await this.updateRecordingStatus(
        cameraId,
        false,
        `Recording stopped at ${new Date().toISOString()}`,
        this.recordings.get(cameraId)
      );
      logger.info(`Stopped recording for camera ${cameraId}`);
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      logger.error(`Failed to stop recording for camera ${cameraId}:`, error);
      await this.updateRecordingStatus(
        cameraId,
        false,
        `Error stopping recording: ${errorMessage}`,
        this.recordings.get(cameraId)
      );
      throw error;
    }
  }

  /**
   * Handles completion of a video segment
   */
  private async handleSegmentComplete(segmentInfo: {
    cameraId: string;
    segmentPath: string;
    isEncrypted: boolean;
    sizeBytes: number;
    durationMs: number;
  }): Promise<void> {
    const { cameraId, segmentPath, isEncrypted, sizeBytes, durationMs } = segmentInfo;
    
    try {
      // Update recording stats
      const recording = this.recordings.get(cameraId);
      if (recording) {
        recording.segmentsRecorded++;
        recording.bytesRecorded += sizeBytes;
        recording.lastSegmentTime = new Date();
      }

      // Get camera details
      const camera = await db.camera.findUnique({ where: { id: cameraId } });
      if (!camera) {
        logger.error(`Camera ${cameraId} not found for segment upload`);
        return;
      }

      // Skip upload if no Google Drive folder is configured
      if (!camera.drive_folder_id) {
        logger.debug(`No Google Drive folder configured for camera ${cameraId}, deleting segment`);
        await storageService.deleteFile(segmentPath).catch((error: Error) => 
          logger.error(`Failed to delete segment ${segmentPath}:`, error)
        );
        return;
      }

      // Create a date-based folder structure (YYYY/MM/DD)
      const now = new Date();
      const datePath = `${now.getFullYear()}/${String(now.getMonth() + 1).padStart(2, '0')}/${String(now.getDate()).padStart(2, '0')}`;
      
      // Queue the file for upload
      const fileName = path.basename(segmentPath);
      const uploadResult = await uploadService.uploadFile({
        filePath: segmentPath,
        fileName,
        folderId: camera.drive_folder_id,
        mimeType: isEncrypted ? 'application/octet-stream' : 'video/mp4',
        deleteAfterUpload: true
      });

      // Update recording stats based on upload result
      if (uploadResult.success) {
        if (recording) {
          recording.segmentsUploaded++;
        }
        logger.info(`Uploaded segment ${fileName} for camera ${cameraId}`, { 
          fileId: uploadResult.fileId,
          size: (sizeBytes / (1024 * 1024)).toFixed(2) + 'MB',
          duration: (durationMs / 1000).toFixed(2) + 's'
        });
      } else {
        if (recording) {
          recording.segmentsFailed++;
        }
        logger.error(`Failed to upload segment ${fileName} for camera ${cameraId}: ${uploadResult.error}`);
      }
      
      // Update recording status in database with current segment info
      const segmentInfo = `Segment ${recording?.segmentsRecorded || 0} uploaded`;
      await this.updateRecordingStatus(
        cameraId,
        true,
        `${segmentInfo} - ${(sizeBytes / (1024 * 1024)).toFixed(2)}MB`,
        this.recordings.get(cameraId)
      );
      
      // Check storage and clean up if needed
      await this.checkAndCleanStorage();
      
    } catch (error) {
      logger.error(`Error handling segment for camera ${cameraId}:`, error);
      
      // Update camera status with the error
      await this.updateCameraStatus(cameraId, true, `Upload error: ${error.message}`);
      
      // Don't rethrow to prevent worker crashes on upload failures
    }
  }

// ...

  private async getCamera(cameraId: string): Promise<Camera | null> {
    try {
      const result = await db.camera.findUnique({ where: { id: cameraId } });
      return result;
    } catch (error) {
      logger.error(`Error fetching camera ${cameraId}:`, error);
      return null;
    }
  }

  /**
   * Updates the camera status in the database
   */
  private async updateCameraStatus(
    cameraId: string,
    isRecording: boolean,
    statusMessage: string
  ): Promise<void> {
    try {
      await db.camera.update({
        where: { id: cameraId },
        data: {
          is_recording: isRecording,
          status: statusMessage,
          updated_at: new Date()
        }
      });
      logger.debug(`Updated camera ${cameraId} status: ${statusMessage}`);
    } catch (error) {
      logger.error(`Failed to update camera ${cameraId} status:`, error);
      // Don't throw to prevent cascading failures
    }
  }

  /**
   * Updates the recording status in both memory and database
   */
  private async updateRecordingStatus(
    cameraId: string,
    isRecording: boolean,
    statusMessage: string,
    recordingStatus?: RecordingStatus
  ): Promise<void> {
    try {
      const currentStatus = recordingStatus || this.recordings.get(cameraId) || {
        isRecording: false,
        segmentsRecorded: 0,
        segmentsUploaded: 0,
        segmentsFailed: 0,
        bytesRecorded: 0,
        lastSegmentTime: new Date()
      };
      
      // Update the local recordings map
      this.recordings.set(cameraId, {
        ...currentStatus,
        isRecording,
        lastUploadStatus: statusMessage,
        lastHeartbeat: new Date()
      });

      await db.camera.update({
        where: { id: cameraId },
        data: {
          is_recording: isRecording,
          last_upload_status: statusMessage,
          segments_recorded: currentStatus.segmentsRecorded,
          segments_uploaded: currentStatus.segmentsUploaded,
          segments_failed: currentStatus.segmentsFailed,
          bytes_recorded: currentStatus.bytesRecorded,
          last_segment_time: currentStatus.lastSegmentTime || new Date(),
          updated_at: new Date()
        }
      });

      // Update camera status in database
      await this.updateCameraStatus(cameraId, isRecording, statusMessage);
      
      // Emit status update event
      this.emit('statusUpdate', {
        cameraId,
        isRecording,
        status: statusMessage,
        ...currentStatus
      });

    } catch (err) {
      const error = err as Error;
      logger.error(`Error updating status for camera ${cameraId}:`, error);
    }
  }

  /**
   * Checks storage usage and cleans up old files if necessary
   */
  private async checkAndCleanStorage(): Promise<void> {
    try {
      const metrics = await storageService.updateMetrics();
      const usagePercent = metrics.usagePercentage;
      
      if (usagePercent >= this.STORAGE_CLEANUP_THRESHOLD * 100) {
        logger.warn(`Storage usage at ${usagePercent.toFixed(2)}%, cleaning up old recordings...`);
        
        // Delete recordings older than retention period
        const cutoffDate = new Date();
        cutoffDate.setDate(cutoffDate.getDate() - this.SEGMENT_RETENTION_DAYS);
        
        const storageDir = process.env.STORAGE_DIR || './storage';
        const recordingsDir = path.join(storageDir, 'recordings');
        const cameraDirs = await fs.promises.readdir(recordingsDir, { withFileTypes: true });
        
        for (const cameraDir of cameraDirs) {
          if (!cameraDir.isDirectory()) continue;
          
          const cameraPath = path.join(recordingsDir, cameraDir.name);
          const files = await fs.promises.readdir(cameraPath);
          
          for (const file of files) {
            const filePath = path.join(cameraPath, file);
            const stats = await fs.promises.stat(filePath);
            
            if (stats.birthtime < cutoffDate) {
              try {
                await storageService.deleteFile(filePath);
                logger.debug(`Deleted old recording: ${filePath}`);
              } catch (err) {
                const error = err as Error;
                logger.error(`Failed to delete old recording ${filePath}:`, error);
              }
            }
          }
        }
        
        logger.info('Storage cleanup completed');
      }
    } catch (err) {
      const error = err as Error;
      logger.error('Error during storage cleanup check:', error);
    }
  }

  private async decryptPassword(encryptedPassword: string): Promise<string> {
    try {
      // Use the encryption service to decrypt the password
      return await EncryptionService.decryptText(encryptedPassword);
    } catch (error) {
      logger.error('Error decrypting password:', error);
      throw new Error('Failed to decrypt password');
    }
  }

  /**
   * Gracefully shuts down the worker
   */
  public async close(): Promise<void> {
    try {
      logger.info('Shutting down recording worker...');
      
      // Stop all active recordings
      for (const [cameraId, recording] of this.recordings.entries()) {
        if (recording.isRecording) {
          try {
            await recordingService.stopRecording(cameraId);
            await this.updateCameraStatus(cameraId, false, 'Recording stopped during shutdown');
            logger.info(`Stopped recording for camera ${cameraId}`);
          } catch (error) {
            logger.error(`Error stopping recording for camera ${cameraId}:`, error);
          }
        }
      }
      
      // Close the worker
      await this.worker.close();
      
      logger.info('Recording worker shutdown complete');
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      logger.error(`Error in recording worker job: ${errorMessage}`);
      throw error;
    }
  }
}

// Initialize the worker when this module is imported
export const recordingWorker = RecordingWorker.getInstance();

// Handle process termination
const shutdown = async (signal: string) => {
  logger.info(`${signal} received, shutting down recording worker...`);
  
  try {
    await recordingWorker.close();
    logger.info('Recording worker shutdown complete');
    process.exit(0);
  } catch (error) {
    logger.error('Error during shutdown:', error);
    process.exit(1);
  }
};

// Handle process termination
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));

// Handle uncaught exceptions
process.on('uncaughtException', (error) => {
  logger.error('Uncaught exception:', error);
  // Don't exit immediately, allow the process to continue
});

// Handle unhandled promise rejections
process.on('unhandledRejection', (reason, promise) => {
  logger.error('Unhandled rejection at:', promise, 'reason:', reason);
});
