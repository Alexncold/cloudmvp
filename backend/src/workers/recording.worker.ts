import { Worker, Job } from 'bullmq';
import { logger } from '../utils/logger';
import { recordingService } from '../services/recording.service';
import { StorageService } from '../services/storage.service';
import { DriveService } from '../services/drive.service';
import { Camera } from '../../shared/types/camera';
import { db } from '../database/db';

interface RecordingJobData {
  cameraId: string;
  action: 'start' | 'stop' | 'restart';
}

export class RecordingWorker {
  private worker: Worker<RecordingJobData, void, string>;
  private static instance: RecordingWorker;

  private constructor() {
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
      const camera = await this.getCamera(cameraId);
      if (!camera) {
        throw new Error(`Camera ${cameraId} not found`);
      }

      if (!camera.rtsp_url) {
        throw new Error(`No RTSP URL configured for camera ${cameraId}`);
      }

      // Create output directory for this camera
      const outputDir = path.join(process.env.STORAGE_DIR || './storage', 'recordings', cameraId);
      await StorageService.ensureDirectoryExists(outputDir);

      // Start recording
      await recordingService.startRecording({
        cameraId,
        rtspUrl: camera.rtsp_url,
        segmentDuration: parseInt(process.env.SEGMENT_DURATION || '300'), // 5 minutes by default
        outputDir,
        enableEncryption: camera.encryption_enabled || false,
        username: camera.username || undefined,
        password: camera.password ? await this.decryptPassword(camera.password) : undefined
      });

      // Update camera status in the database
      await this.updateCameraStatus(cameraId, true);
      
      logger.info(`Started recording for camera ${cameraId}`);
    } catch (error) {
      logger.error(`Failed to start recording for camera ${cameraId}:`, error);
      await this.updateCameraStatus(cameraId, false, error.message);
      throw error;
    }
  }

  private async stopRecording(cameraId: string): Promise<void> {
    try {
      await recordingService.stopRecording(cameraId);
      await this.updateCameraStatus(cameraId, false);
      logger.info(`Stopped recording for camera ${cameraId}`);
    } catch (error) {
      logger.error(`Failed to stop recording for camera ${cameraId}:`, error);
      throw error;
    }
  }

  private async handleSegmentComplete(segmentInfo: {
    cameraId: string;
    segmentPath: string;
    isEncrypted: boolean;
  }): Promise<void> {
    const { cameraId, segmentPath, isEncrypted } = segmentInfo;
    
    try {
      // Get camera details
      const camera = await this.getCamera(cameraId);
      if (!camera) {
        logger.error(`Camera ${cameraId} not found for segment upload`);
        return;
      }

      // Skip upload if no Google Drive folder is configured
      if (!camera.drive_folder_id) {
        logger.debug(`No Google Drive folder configured for camera ${cameraId}, skipping upload`);
        return;
      }

      // Upload to Google Drive
      const driveService = DriveService.getInstance();
      const fileName = path.basename(segmentPath);
      
      // Create a date-based folder structure (YYYY/MM/DD)
      const now = new Date();
      const datePath = `${now.getFullYear()}/${String(now.getMonth() + 1).padStart(2, '0')}/${String(now.getDate()).padStart(2, '0')}`;
      
      // Upload the file
      await driveService.uploadFile({
        filePath: segmentPath,
        fileName,
        folderId: camera.drive_folder_id,
        parentPath: datePath,
        mimeType: isEncrypted ? 'application/octet-stream' : 'video/mp4'
      });

      logger.debug(`Uploaded segment ${fileName} to Google Drive for camera ${cameraId}`);
      
      // Delete the local file after successful upload
      await StorageService.deleteFile(segmentPath);
      
    } catch (error) {
      logger.error(`Error handling segment for camera ${cameraId}:`, error);
      
      // Update camera status with the error
      await this.updateCameraStatus(cameraId, true, `Upload error: ${error.message}`);
      
      // Don't rethrow to prevent worker crashes on upload failures
    }
  }

  private async getCamera(cameraId: string): Promise<Camera | null> {
    try {
      const result = await db.oneOrNone(
        'SELECT * FROM cameras WHERE id = $1',
        [cameraId]
      );
      return result;
    } catch (error) {
      logger.error(`Error fetching camera ${cameraId}:`, error);
      return null;
    }
  }

  private async updateCameraStatus(
    cameraId: string, 
    isRecording: boolean, 
    errorMessage: string | null = null
  ): Promise<void> {
    try {
      await db.none(
        `UPDATE cameras 
         SET is_recording = $1, 
             last_upload_status = $2,
             updated_at = NOW()
         WHERE id = $3`,
        [isRecording, errorMessage, cameraId]
      );
    } catch (error) {
      logger.error(`Error updating status for camera ${cameraId}:`, error);
    }
  }

  private async decryptPassword(encryptedPassword: string): Promise<string> {
    try {
      // This assumes you have an encryption service that can decrypt the password
      // You'll need to implement this based on your encryption method
      return encryptedPassword; // Replace with actual decryption
    } catch (error) {
      logger.error('Error decrypting password:', error);
      throw new Error('Failed to decrypt password');
    }
  }

  public async close(): Promise<void> {
    await this.worker.close();
  }
}

// Initialize the worker when this module is imported
export const recordingWorker = RecordingWorker.getInstance();

// Handle process termination
process.on('SIGTERM', async () => {
  logger.info('SIGTERM received, shutting down recording worker...');
  await recordingWorker.close();
  process.exit(0);
});

process.on('SIGINT', async () => {
  logger.info('SIGINT received, shutting down recording worker...');
  await recordingWorker.close();
  process.exit(0);
});
