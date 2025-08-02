import { describe, it, expect, beforeAll, afterAll, jest, beforeEach, afterEach } from '@jest/globals';
import { Worker } from 'bullmq';
import path from 'path';
import fs from 'fs/promises';
import { EventEmitter } from 'events';
import { recordingWorker } from '../../src/workers/recording.worker';
import { recordingService } from '../../src/services/recording.service';
import { storageService } from '../../src/services/storage.service';
import { uploadService } from '../../src/services/upload.service';
import { db } from '../../src/services/db';
import { logger } from '../../src/utils/logger';

// Extend the test timeout for integration tests
jest.setTimeout(30000);

// Mock the recording service
jest.mock('../../src/services/recording.service');
jest.mock('../../src/services/upload.service');

// Mock the logger to avoid cluttering test output
jest.mock('../../src/utils/logger', () => ({
  info: jest.fn(),
  error: jest.fn(),
  debug: jest.fn(),
  warn: jest.fn(),
}));

describe('Integration: Recording Worker', () => {
  let worker: typeof recordingWorker;
  
  // Test camera data
  const testCamera = {
    id: 'test-camera-1',
    name: 'Test Camera',
    rtsp_url: 'rtsp://test-stream:8554/test',
    is_active: true,
    encryption_enabled: false,
    drive_folder_id: 'test-folder-id',
  };

  beforeAll(async () => {
    // Set up any required test environment
    process.env.STORAGE_DIR = path.join(__dirname, '..', 'test-storage');
    process.env.SEGMENT_DURATION = '10'; // 10 seconds for testing
    
    // Ensure test storage directory exists
    await fs.mkdir(process.env.STORAGE_DIR, { recursive: true });
    
    // Mock database responses
    jest.spyOn(db.camera, 'findUnique').mockImplementation(async (options) => {
      return options.where.id === testCamera.id ? testCamera : null;
    });
    
    jest.spyOn(db.camera, 'update').mockImplementation(async (options) => ({
      ...testCamera,
      ...options.data,
    }));
    
    // Mock storage service
    jest.spyOn(storageService, 'ensureDirectoryExists').mockResolvedValue(undefined);
    jest.spyOn(storageService, 'updateMetrics').mockResolvedValue({
      totalSpace: 1000000000, // 1GB
      usedSpace: 100000000,   // 100MB
      freeSpace: 900000000,   // 900MB
      usagePercentage: 10,
      filesCount: 10,
      lastCleanup: new Date(),
      nextCleanup: new Date(Date.now() + 3600000), // 1 hour from now
    });
    
    // Mock upload service
    (uploadService.uploadFile as jest.Mock).mockResolvedValue({
      success: true,
      fileId: 'test-file-id',
    });
    
    // Initialize the worker
    worker = recordingWorker;
  });
  
  afterAll(async () => {
    // Clean up test storage
    try {
      await fs.rm(process.env.STORAGE_DIR!, { recursive: true, force: true });
    } catch (error) {
      console.error('Error cleaning up test storage:', error);
    }
    
    // Close the worker
    await worker.close();
    
    // Clear all mocks
    jest.clearAllMocks();
  });
  
  beforeEach(() => {
    // Reset mocks before each test
    jest.clearAllMocks();
  });
  
  describe('Recording Lifecycle', () => {
    it('should start recording for a camera', async () => {
      // Mock the recording service
      (recordingService.startRecording as jest.Mock).mockResolvedValue(undefined);
      
      // Start recording
      await worker['startRecording'](testCamera.id);
      
      // Verify recording was started
      expect(recordingService.startRecording).toHaveBeenCalledWith(
        expect.objectContaining({
          cameraId: testCamera.id,
          rtspUrl: testCamera.rtsp_url,
          enableEncryption: testCamera.encryption_enabled,
        })
      );
      
      // Verify recording status was updated
      expect(db.camera.update).toHaveBeenCalledWith(
        expect.objectContaining({
          where: { id: testCamera.id },
          data: expect.objectContaining({
            is_recording: true,
          }),
        })
      );
    });
    
    it('should handle recording errors', async () => {
      // Mock a recording error
      const error = new Error('Failed to start recording');
      (recordingService.startRecording as jest.Mock).mockRejectedValue(error);
      
      // Attempt to start recording
      await expect(worker['startRecording'](testCamera.id)).rejects.toThrow(error);
      
      // Verify error was logged
      expect(logger.error).toHaveBeenCalledWith(
        `Failed to start recording for camera ${testCamera.id}:`,
        error
      );
    });
    
    it('should stop recording for a camera', async () => {
      // Mock the recording service
      (recordingService.stopRecording as jest.Mock).mockResolvedValue(undefined);
      
      // Stop recording
      await worker['stopRecording'](testCamera.id);
      
      // Verify recording was stopped
      expect(recordingService.stopRecording).toHaveBeenCalledWith(testCamera.id);
      
      // Verify recording status was updated
      expect(db.camera.update).toHaveBeenCalledWith(
        expect.objectContaining({
          where: { id: testCamera.id },
          data: expect.objectContaining({
            is_recording: false,
          }),
        })
      );
    });
  });
  
  describe('Segment Handling', () => {
    it('should handle segment completion and upload', async () => {
      const segmentInfo = {
        cameraId: testCamera.id,
        segmentPath: path.join(process.env.STORAGE_DIR!, 'test-segment.mp4'),
        isEncrypted: false,
        sizeBytes: 1024 * 1024, // 1MB
        durationMs: 10000, // 10 seconds
      };
      
      // Mock file existence
      jest.spyOn(fs, 'access').mockResolvedValue(undefined);
      
      // Handle segment completion
      await worker['handleSegmentComplete'](segmentInfo);
      
      // Verify file was uploaded
      expect(uploadService.uploadFile).toHaveBeenCalledWith(
        expect.objectContaining({
          filePath: segmentInfo.segmentPath,
          folderId: testCamera.drive_folder_id,
          mimeType: 'video/mp4',
          deleteAfterUpload: true,
        })
      );
      
      // Verify recording status was updated
      expect(db.camera.update).toHaveBeenCalledWith(
        expect.objectContaining({
          where: { id: testCamera.id },
          data: expect.objectContaining({
            is_recording: true,
          }),
        })
      );
    });
    
    it('should handle upload failures', async () => {
      const segmentInfo = {
        cameraId: testCamera.id,
        segmentPath: path.join(process.env.STORAGE_DIR!, 'test-segment.mp4'),
        isEncrypted: false,
        sizeBytes: 1024 * 1024, // 1MB
        durationMs: 10000, // 10 seconds
      };
      
      // Mock upload failure
      (uploadService.uploadFile as jest.Mock).mockResolvedValueOnce({
        success: false,
        error: 'Upload failed',
      });
      
      // Handle segment completion
      await worker['handleSegmentComplete'](segmentInfo);
      
      // Verify error was logged
      expect(logger.error).toHaveBeenCalledWith(
        expect.stringContaining('Failed to upload segment'),
        expect.anything()
      );
    });
  });
  
  describe('Storage Management', () => {
    it('should clean up old recordings when storage is full', async () => {
      // Mock high storage usage
      (storageService.updateMetrics as jest.Mock).mockResolvedValueOnce({
        totalSpace: 1000000000, // 1GB
        usedSpace: 900000000,   // 900MB (90% usage)
        freeSpace: 100000000,   // 100MB
        usagePercentage: 90,
        filesCount: 90,
        lastCleanup: new Date(),
        nextCleanup: new Date(),
      });
      
      // Mock directory listing
      const oldFile = {
        name: 'old-recording.mp4',
        isDirectory: () => false,
        birthtime: new Date(Date.now() - 8 * 24 * 60 * 60 * 1000), // 8 days old
      };
      
      const newFile = {
        name: 'new-recording.mp4',
        isDirectory: () => false,
        birthtime: new Date(), // Current time
      };
      
      // Mock file system operations
      jest.spyOn(fs, 'readdir').mockImplementation(async (dirPath, options) => {
        return ['camera1', 'camera2'];
      });
      
      jest.spyOn(fs, 'readdir').mockImplementationOnce(async (dirPath, options) => {
        return [oldFile, newFile] as any;
      });
      
      jest.spyOn(fs, 'stat').mockImplementation(async (filePath) => {
        return {
          isDirectory: () => false,
          birthtime: filePath.toString().includes('old') ? 
            new Date(Date.now() - 8 * 24 * 60 * 60 * 1000) : 
            new Date(),
          size: 1024 * 1024, // 1MB
        } as any;
      });
      
      jest.spyOn(storageService, 'deleteFile').mockResolvedValue(undefined);
      
      // Trigger storage check
      await worker['checkAndCleanStorage']();
      
      // Verify old file was deleted
      expect(storageService.deleteFile).toHaveBeenCalledWith(
        expect.stringContaining('old-recording.mp4')
      );
      
      // Verify new file was not deleted
      expect(storageService.deleteFile).not.toHaveBeenCalledWith(
        expect.stringContaining('new-recording.mp4')
      );
    });
  });
});
