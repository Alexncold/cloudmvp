import { google, drive_v3 } from 'googleapis';
import { JWT } from 'google-auth-library';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { Readable } from 'stream';
import { logger } from '../utils/logger';
import { v4 as uuidv4 } from 'uuid';
import { createCipheriv, randomBytes } from 'crypto';

// Type definitions for Google Drive API
type DriveFile = drive_v3.Schema$File;

export interface DriveFileMetadata {
  id: string;
  name: string;
  mimeType: string;
  size: number;
  webViewLink?: string;
  createdTime: string;
  modifiedTime: string;
  isEncrypted?: boolean;
  md5Checksum?: string;
  parents?: string[];
  webContentLink?: string;
  encryptionKeyId?: string;
  iv?: string;
}

export interface UploadFileOptions {
  filePath: string;
  fileName: string;
  folderId: string;
  parentPath?: string[];
  mimeType?: string;
  isPublic?: boolean;
  encrypt?: boolean;
  metadata?: Record<string, string>;
}

export interface QuotaInfo {
  limit: number; // in bytes
  usage: number; // in bytes
  usageInDrive: number; // in bytes
  usageInDriveTrash: number; // in bytes
  remaining: number; // in bytes
  isLow: boolean;
  lastUpdated: Date;
}

export interface DriveServiceConfig {
  serviceAccountEmail: string;
  serviceAccountKey: string;
  rootFolderId?: string;
  encryptionKey?: string;
  tempDir?: string;
}

// Constants
const UPLOAD_RETRY_ATTEMPTS = 3;
const UPLOAD_RETRY_DELAY_MS = 2000; // 2 seconds
const QUOTA_CHECK_THRESHOLD_BYTES = 100 * 1024 * 1024; // 100MB

// Simple sleep function for retries
const sleep = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));

export interface CreateFolderOptions {
  name: string;
  parentId?: string;
  description?: string;
}

export class DriveService {
  private static instance: DriveService;
  private drive: drive_v3.Drive;
  private auth: JWT;
  private serviceAccountEmail: string;
  private serviceAccountKey: string;
  private initialized = false;
  private quotaInfo: QuotaInfo | null = null;
  private lastQuotaCheck: Date | null = null;
  private encryptionKey: Buffer | null = null; // In production, use a KMS or secure secret manager
  private rootFolderId?: string;

  private constructor() {
    // Initialize with empty values, will be set in initialize()
    this.serviceAccountEmail = process.env.GOOGLE_SERVICE_ACCOUNT_EMAIL || '';
    this.serviceAccountKey = process.env.GOOGLE_SERVICE_ACCOUNT_KEY || '';
    this.auth = new google.auth.OAuth2();
    this.drive = google.drive({ version: 'v3', auth: this.auth });
  }

  public static getInstance(): DriveService {
    if (!DriveService.instance) {
      DriveService.instance = new DriveService();
    }
    return DriveService.instance;
  }

  public async initialize(encryptionKey?: string, rootFolderId?: string): Promise<void> {
    if (this.initialized) return;

    try {
      if (!this.serviceAccountEmail || !this.serviceAccountKey) {
        throw new Error('Google service account credentials not configured');
      }

      // Create a JWT client for service account authentication
      this.auth = new JWT(
        this.serviceAccountEmail,
        undefined,
        this.serviceAccountKey.replace(/\\n/g, '\n'),
        ['https://www.googleapis.com/auth/drive'],
        undefined,
        undefined,
        'private_key',
        'RS256'
      );

      // Initialize the Google Drive API
      this.drive = google.drive({ 
        version: 'v3', 
        auth: this.auth,
        retry: true,
        retryConfig: {
          retry: 3,
          retryDelay: (retryCount) => Math.pow(2, retryCount) * 1000, // Exponential backoff
          httpMethodsToRetry: ['GET', 'PUT', 'POST', 'PATCH', 'DELETE'],
          statusCodesToRetry: [[100, 199], [429, 429], [500, 599]]
        }
      });
      
      // Test the connection and get initial quota info
      await this.checkQuota(true);
      
      // Set up periodic quota check (every 5 minutes)
      setInterval(() => this.checkQuota(), 5 * 60 * 1000);
      
      // Initialize encryption if key is provided
      if (encryptionKey) {
        this.encryptionKey = Buffer.from(encryptionKey, 'base64');
        if (this.encryptionKey.length !== 32) {
          logger.warn('Encryption key should be 32 bytes (256 bits) for AES-256');
        }
      }
      
      this.rootFolderId = rootFolderId;
      
      this.initialized = true;
      logger.info('Google Drive service initialized successfully');
    } catch (error) {
      const errorMsg = error instanceof Error ? error.message : 'Unknown error';
      logger.error('Failed to initialize Google Drive service:', { 
        error: errorMsg,
        stack: error instanceof Error ? error.stack : undefined
      });
      throw new Error(`Failed to initialize Google Drive: ${errorMsg}`);
    }
  }

  private async retryWithBackoff<T>(
    operation: () => Promise<T>,
    maxRetries = UPLOAD_RETRY_ATTEMPTS,
    initialDelayMs = UPLOAD_RETRY_DELAY_MS,
    retryCount = 0
  ): Promise<T> {
    try {
      return await operation();
    } catch (error) {
      if (retryCount >= maxRetries) {
        throw error;
      }
      await sleep(initialDelayMs * Math.pow(2, retryCount));
      return this.retryWithBackoff(operation, maxRetries, initialDelayMs, retryCount + 1);
    }
  }

  /**
   * Checks the current Drive quota and updates the cache
   * @param forceRefresh Force a refresh of the quota info
   */
  private async checkQuota(forceRefresh = false): Promise<QuotaInfo> {
    const now = new Date();
    
    // Return cached quota info if it's recent enough and not forcing refresh
    if (!forceRefresh && this.quotaInfo && this.lastQuotaCheck) {
      const timeSinceLastCheck = now.getTime() - this.lastQuotaCheck.getTime();
      if (timeSinceLastCheck < 5 * 60 * 1000) { // 5 minutes
        return this.quotaInfo;
      }
    }
    
    try {
      const about = await this.drive.about.get({
        fields: 'storageQuota(limit,usage,usageInDrive,usageInDriveTrash)'
      });
      
      const quota = about.data.storageQuota!;
      const limit = parseInt(quota.limit || '0', 10);
      const usage = parseInt(quota.usage || '0', 10);
      const remaining = Math.max(0, limit - usage);
      
      this.quotaInfo = {
        limit,
        usage,
        remaining,
        usageInDrive: parseInt(quota.usageInDrive || '0', 10),
        usageInDriveTrash: parseInt(quota.usageInDriveTrash || '0', 10),
        lastUpdated: now,
        isLow: remaining < QUOTA_CHECK_THRESHOLD_BYTES
      };
      
      this.lastQuotaCheck = now;
      
      // Log if quota is low
      if (this.quotaInfo.isLow) {
        const remainingGB = (this.quotaInfo.remaining / (1024 * 1024 * 1024)).toFixed(2);
        logger.warn(`Google Drive quota is low: ${remainingGB}GB remaining`);
      }
      
      return this.quotaInfo;
      
    } catch (error) {
      logger.error('Error checking Google Drive quota:', { 
        error: error instanceof Error ? error.message : 'Unknown error' 
      });
      
      // If we have cached quota info, return it with a warning
      if (this.quotaInfo) {
        logger.warn('Using cached quota info due to error');
        return this.quotaInfo;
      }
      
      throw new Error(`Failed to check Google Drive quota: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }
  
  /**
   * Ensures there's enough quota available for an upload
   * @param requiredBytes Number of bytes required
   * @throws Error if there's not enough quota
   */
  private async ensureSufficientQuota(requiredBytes: number): Promise<void> {
    const quota = await this.checkQuota();
    
    if (quota.remaining < requiredBytes) {
      const requiredGB = (requiredBytes / (1024 * 1024 * 1024)).toFixed(2);
      const remainingGB = (quota.remaining / (1024 * 1024 * 1024)).toFixed(2);
      
      const errorMsg = `Insufficient Google Drive quota. Required: ${requiredGB}GB, Available: ${remainingGB}GB`;
      logger.error(errorMsg, { 
        requiredBytes, 
        quota: {
          limit: quota.limit,
          usage: quota.usage,
          remaining: quota.remaining,
          isLow: quota.isLow
        } 
      });
      throw new Error(errorMsg);
    }
  }
  
  /**
   * Encrypts a file using AES-256-GCM
   * @param inputFile Path to the input file
   * @param outputFile Path to save the encrypted file
   * @returns Object containing the initialization vector and encryption key ID
   */
  private async encryptFile(
    inputPath: string,
    outputPath: string,
    key: Buffer
  ): Promise<{ iv: Buffer; authTag: Buffer }> {
    return new Promise((resolve, reject) => {
      try {
        // Generate a random IV
        const iv = randomBytes(12);
        
        // Create cipher
        const cipher = createCipheriv('aes-256-gcm', key, iv, { authTagLength: 16 });
        
        // Create read/write streams
        const input = fs.createReadStream(inputPath);
        const output = fs.createWriteStream(outputPath);
        
        // Write IV to the beginning of the output file
        output.write(iv);
        
        // Pipe data through cipher to output
        input.pipe(cipher).pipe(output);
        
        // Handle completion
        output.on('finish', () => {
          const authTag = cipher.getAuthTag();
          if (!authTag) {
            reject(new Error('Failed to get authentication tag'));
            return;
          }
          resolve({
            iv,
            authTag
          });
        });
        
        // Handle errors
        input.on('error', (error: Error) => reject(error));
        cipher.on('error', (error: Error) => reject(error));
        output.on('error', (error: Error) => reject(error));
        
      } catch (error) {
        reject(error instanceof Error ? error : new Error(String(error)));
      }
    });
  }
  
  /**
   * Uploads a file to Google Drive with retry and quota handling
   */
  public async uploadFile(options: UploadFileOptions): Promise<DriveFileMetadata> {
    if (!this.initialized) {
      await this.initialize();
    }

    const { filePath, fileName, folderId, parentPath, mimeType = 'application/octet-stream' } = options;
    
    // Check file size and quota before proceeding
    const stats = await fs.promises.stat(filePath);
    const fileSize = stats.size;
    
    // Verify we have enough quota (add 10% buffer for encryption overhead if enabled)
    const requiredBytes = this.encryptionKey ? Math.ceil(fileSize * 1.1) : fileSize;
    await this.ensureSufficientQuota(requiredBytes);
    
    let lastError: Error | null = null;
    let tempFilePath: string | null = null;
    let uploadFilePath = filePath;
    let encryptionInfo: { iv: Buffer; authTag: Buffer } | null = null;
    
    // Clean up temp files on exit
    const cleanup = () => {
      if (tempFilePath && fs.existsSync(tempFilePath)) {
        try {
          fs.unlinkSync(tempFilePath);
        } catch (error) {
          const errorMessage = error instanceof Error ? error.message : 'Unknown error';
          logger.warn('Failed to clean up temp file', { 
            tempFilePath, 
            error: errorMessage 
          });
        }
      }
    };

    // Ensure we clean up temp files on error
    process.on('exit', cleanup);
    process.on('SIGINT', () => {
      cleanup();
      process.exit(1);
    });
    
    try {
      // Encrypt the file if encryption is enabled
      let uploadFilePath = filePath;
      let encryptionInfo = {};
      
      if (this.encryptionKey) {
        tempFilePath = path.join(os.tmpdir(), `encrypted-${uuidv4()}`);
        encryptionInfo = await this.encryptFile(filePath, tempFilePath, this.encryptionKey);
        uploadFilePath = tempFilePath;
      }
      
      // Retry logic for uploads
      for (let attempt = 1; attempt <= UPLOAD_RETRY_ATTEMPTS; attempt++) {
        try {
          // Get the target folder ID (create subfolders if needed)
          let targetFolderId = folderId;
          if (parentPath) {
            targetFolderId = await this.ensureFolderPath(parentPath, targetFolderId);
          }

          // Check if file already exists
          const existingFileId = await this.findFile(fileName, targetFolderId);
          
          // Prepare file metadata
          const fileMetadata: drive_v3.Params$Resource$Files$Create['requestBody'] = {
            name: fileName,
            parents: [targetFolderId],
            mimeType,
            description: `Uploaded by CloudCam on ${new Date().toISOString()}`,
            appProperties: {
              'cloudcamUploaded': 'true',
              'uploadTimestamp': Date.now().toString(),
              'originalFilename': fileName,
            },
          };
          
          // Upload the file
          const file = await this.drive.files.create({
            requestBody: fileMetadata,
            media: {
              mimeType,
              body: fs.createReadStream(uploadFilePath),
            },
            fields: 'id, name, mimeType, webViewLink, webContentLink',
          });
          
          // Update quota info after upload
          await this.checkQuota(true);
          
          // Return file metadata
          return {
            id: file.data.id!,
            name: file.data.name || 'Unnamed file',
            mimeType: file.data.mimeType || 'application/octet-stream',
            size: fileSize,
            createdTime: file.data.createdTime || new Date().toISOString(),
            modifiedTime: file.data.modifiedTime || new Date().toISOString(),
            webViewLink: file.data.webViewLink || undefined,
            webContentLink: file.data.webContentLink || undefined,
            isEncrypted: !!this.encryptionKey,
            encryptionKeyId: this.encryptionKey ? 'default' : undefined,
            iv: this.encryptionKey ? encryptionInfo.iv.toString('base64') : undefined,
          };
        
        } catch (error) {
          lastError = error;
          await sleep(UPLOAD_RETRY_DELAY_MS);
        }
      }
      
      // If all retries fail, throw the last error
      if (lastError) {
        throw lastError;
      }
      
    } catch (error) {
      logger.error('Error uploading file to Google Drive:', { 
        error: error instanceof Error ? error.message : 'Unknown error',
        stack: error instanceof Error ? error.stack : undefined,
        filePath,
        fileName,
        folderId,
        parentPath
      });
      throw new Error(`Failed to upload file: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Creates a folder structure in Google Drive
   * @param baseFolderId The ID of the base folder
   * @param folderPath The folder path to create (e.g., '2023/07/28')
   * @returns The ID of the deepest folder in the path
   */
  /**
   * Ensures a folder path exists in Google Drive, creating any missing folders
   * @param folderPath Array of folder names in the path
   * @param parentId Optional parent folder ID (defaults to root folder)
   * @returns The ID of the deepest folder in the path
   */
  public async ensureFolderPath(folderPath: string[], parentId?: string): Promise<string> {
    if (folderPath.length === 0) {
      return parentId || this.rootFolderId || '';
    }

    const [currentFolder, ...remainingFolders] = folderPath;
    
    try {
      const parentFolderId = parentId || this.rootFolderId;
      if (!parentFolderId) {
        throw new Error('No parent folder ID provided and no root folder ID configured');
      }

      // Check if folder exists
      const query = `name='${currentFolder.replace(/'/g, "\\'")}' and '${parentFolderId}' in parents and mimeType='application/vnd.google-apps.folder' and trashed=false`;
      const response = await this.drive.files.list({
        q: query,
        fields: 'files(id, name)',
        spaces: 'drive',
        pageSize: 1
      });

      let folderId: string;
      
      if (response.data.files && response.data.files.length > 0) {
        // Folder exists, use its ID
        folderId = response.data.files[0].id!;
      } else {
        // Create the folder
        const fileMetadata = {
          name: currentFolder,
          mimeType: 'application/vnd.google-apps.folder',
          parents: [parentFolderId]
        };
        
        const folder = await this.drive.files.create({
          requestBody: fileMetadata,
          fields: 'id, name, mimeType, webViewLink',
        });
        
        if (!folder.data.id) {
          throw new Error(`Failed to create folder: ${currentFolder}`);
        }
        folderId = folder.data.id;
      }
      
      return folderId;
    } catch (error) {
      const errorMsg = error instanceof Error ? error.message : 'Unknown error';
      throw new Error(`Error in ensureFolderPath: ${errorMsg}`);
    }
  }
  
  /**
   * Deletes a file from Google Drive
   */
  public async deleteFile(fileId: string): Promise<void> {
    if (!this.initialized) {
      await this.initialize();
    }
    
    try {
      await this.drive.files.delete({
        fileId,
        supportsAllDrives: true
      });
      
      // Update quota info after deletion
      await this.checkQuota(true);
      
    } catch (error) {
      const errorMsg = error instanceof Error ? error.message : 'Unknown error';
      
      // Ignore "not found" errors (file might have been deleted already)
      if (errorMsg.includes('File not found')) {
        logger.warn(`File not found during deletion: ${fileId}`);
        return;
      }
      
      logger.error('Error deleting file from Google Drive:', { 
        error: errorMsg,
        stack: error instanceof Error ? error.stack : undefined,
        fileId
      });
      
      throw new Error(`Failed to delete file: ${errorMsg}`);
    }
  }
  
  /**
   * Gets the web view link for a file
   */
  public async getFileWebLink(fileId: string): Promise<string | null> {
    if (!this.initialized) {
      await this.initialize();
    }
    
    try {
      const response = await this.drive.files.get({
        fileId,
        fields: 'webViewLink,webContentLink',
        supportsAllDrives: true
      });
      
      return response.data.webViewLink || response.data.webContentLink || null;
      
    } catch (error) {
      const errorMsg = error instanceof Error ? error.message : 'Unknown error';
      logger.error('Error getting file web link:', { 
        error: errorMsg,
        stack: error instanceof Error ? error.stack : undefined,
        fileId
      });
      
      return null;
    }
  }
}

export const driveService = DriveService.getInstance();

// Initialize the service when this module is imported
if (process.env.NODE_ENV !== 'test') {
  const GOOGLE_ENCRYPTION_KEY = process.env.GOOGLE_ENCRYPTION_KEY;
  
  driveService.initialize(GOOGLE_ENCRYPTION_KEY).catch((error: unknown) => {
    const errorMsg = error instanceof Error ? error.message : 'Unknown error';
    const stack = error instanceof Error ? error.stack : undefined;
    
    logger.error('Failed to initialize Google Drive service:', { 
      error: errorMsg,
      stack
    });
    
    // Don't exit in production to allow the app to continue without Drive
    if (process.env.NODE_ENV !== 'production') {
      process.exit(1);
    }
  });
}
