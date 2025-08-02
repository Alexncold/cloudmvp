// Integration test setup
import dotenv from 'dotenv';
import path from 'path';
import { jest } from '@jest/globals';
import { logger } from '../src/utils/logger';

// Load test environment variables
const envPath = path.resolve(__dirname, '../.env.test');
dotenv.config({ path: envPath, override: true });

// Set up global mocks
jest.mock('winston', () => ({
  format: {
    json: jest.fn(),
    timestamp: jest.fn(),
    combine: jest.fn(),
    colorize: jest.fn(),
    printf: jest.fn(),
    simple: jest.fn(),
  },
  createLogger: jest.fn().mockReturnValue({
    info: jest.fn(),
    error: jest.fn(),
    warn: jest.fn(),
    debug: jest.fn(),
  }),
  transports: {
    Console: jest.fn(),
    File: jest.fn(),
  },
}));

// Mock the database
jest.mock('../src/services/db', () => ({
  db: {
    camera: {
      findUnique: jest.fn(),
      update: jest.fn(),
    },
    recording: {
      create: jest.fn(),
      update: jest.fn(),
      findUnique: jest.fn(),
    },
  },
}));

// Mock the recording service
jest.mock('../src/services/recording.service', () => ({
  recordingService: {
    startRecording: jest.fn(),
    stopRecording: jest.fn(),
    on: jest.fn(),
    emit: jest.fn(),
  },
}));

// Mock the storage service
jest.mock('../src/services/storage.service', () => ({
  storageService: {
    ensureDirectoryExists: jest.fn(),
    updateMetrics: jest.fn(),
    deleteFile: jest.fn(),
  },
}));

// Mock the upload service
jest.mock('../src/services/upload.service', () => ({
  uploadService: {
    uploadFile: jest.fn(),
  },
}));

// Mock the encryption service
jest.mock('../src/services/encryption.service', () => ({
  EncryptionService: {
    getInstance: jest.fn().mockReturnValue({
      encryptText: jest.fn().mockResolvedValue('encrypted-text'),
      decryptText: jest.fn().mockResolvedValue('decrypted-text'),
    }),
  },
}));

// Set up test environment
process.env.NODE_ENV = 'test';
process.env.STORAGE_DIR = path.join(__dirname, 'test-storage');
process.env.SEGMENT_DURATION = '10';
process.env.SEGMENT_RETENTION_DAYS = '7';

// Clean up after tests
afterAll(async () => {
  // Clean up any test files or resources
  jest.clearAllMocks();
});

// Helper function to reset all mocks between tests
const resetMocks = () => {
  jest.clearAllMocks();
  
  // Reset default mock implementations
  const { recordingService } = require('../src/services/recording.service');
  const { storageService } = require('../src/services/storage.service');
  const { uploadService } = require('../src/services/upload.service');
  const { db } = require('../src/services/db');
  
  // Reset recording service mocks
  recordingService.startRecording.mockResolvedValue(undefined);
  recordingService.stopRecording.mockResolvedValue(undefined);
  
  // Reset storage service mocks
  storageService.ensureDirectoryExists.mockResolvedValue(undefined);
  storageService.updateMetrics.mockResolvedValue({
    totalSpace: 1000000000, // 1GB
    usedSpace: 100000000,   // 100MB
    freeSpace: 900000000,   // 900MB
    usagePercentage: 10,
    filesCount: 10,
    lastCleanup: new Date(),
    nextCleanup: new Date(Date.now() + 3600000), // 1 hour from now
  });
  storageService.deleteFile.mockResolvedValue(undefined);
  
  // Reset upload service mocks
  uploadService.uploadFile.mockResolvedValue({
    success: true,
    fileId: 'test-file-id',
  });
  
  // Reset database mocks
  db.camera.findUnique.mockImplementation(async (options: any) => ({
    id: options?.where?.id || 'test-camera-1',
    name: 'Test Camera',
    rtsp_url: 'rtsp://test-stream:8554/test',
    is_active: true,
    encryption_enabled: false,
    drive_folder_id: 'test-folder-id',
  }));
  
  db.camera.update.mockImplementation(async (options: any) => ({
    ...options.data,
    id: options.where.id,
  }));
};

export { resetMocks };
