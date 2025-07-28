import { spawn, ChildProcess } from 'child_process';
import { EventEmitter } from 'events';
import fs from 'fs';
import path from 'path';
import { logger } from '../utils/logger';
import { StorageService } from './storage.service';
import { EncryptionService } from './encryption.service';

interface RecordingOptions {
  cameraId: string;
  rtspUrl: string;
  segmentDuration: number; // in seconds
  outputDir: string;
  enableEncryption: boolean;
  username?: string;
  password?: string;
}

export interface RecordingInfo {
  cameraId: string;
  startTime: Date;
  segmentPath: string;
  segmentNumber: number;
  isEncrypted: boolean;
}

export class RecordingService extends EventEmitter {
  private static instance: RecordingService;
  private recordings: Map<string, {
    process: ChildProcess;
    options: RecordingOptions;
    currentSegment: number;
    lastHeartbeat: Date;
    reconnectAttempts: number;
  }> = new Map();

  private readonly MAX_RECONNECT_ATTEMPTS = 5;
  private readonly RECONNECT_DELAY_MS = 5000; // 5 seconds

  private constructor() {
    super();
    logger.info('Recording service initialized');
  }

  public static getInstance(): RecordingService {
    if (!RecordingService.instance) {
      RecordingService.instance = new RecordingService();
    }
    return RecordingService.instance;
  }

  public async startRecording(options: RecordingOptions): Promise<void> {
    const { cameraId, rtspUrl } = options;
    
    if (this.recordings.has(cameraId)) {
      logger.warn(`Recording already in progress for camera ${cameraId}`);
      return;
    }

    logger.info(`Starting recording for camera ${cameraId}`, { rtspUrl });
    
    try {
      await StorageService.ensureDirectoryExists(options.outputDir);
      await this.startFfmpegProcess(cameraId, options);
      logger.info(`Recording started for camera ${cameraId}`);
    } catch (error) {
      logger.error(`Failed to start recording for camera ${cameraId}:`, error);
      throw new Error(`Failed to start recording: ${error.message}`);
    }
  }

  public async stopRecording(cameraId: string): Promise<void> {
    const recording = this.recordings.get(cameraId);
    if (!recording) {
      logger.warn(`No active recording found for camera ${cameraId}`);
      return;
    }

    logger.info(`Stopping recording for camera ${cameraId}`);
    
    try {
      if (recording.process.stdin?.writable) {
        recording.process.stdin.write('q');
      } else {
        recording.process.kill('SIGTERM');
      }
      
      this.recordings.delete(cameraId);
      logger.info(`Recording stopped for camera ${cameraId}`);
      this.emit('recordingStopped', { cameraId });
    } catch (error) {
      logger.error(`Error stopping recording for camera ${cameraId}:`, error);
      throw new Error(`Failed to stop recording: ${error.message}`);
    }
  }

  public getActiveRecordings() {
    return Array.from(this.recordings.entries()).map(([cameraId, { options, lastHeartbeat }]) => ({
      cameraId,
      rtspUrl: options.rtspUrl,
      startTime: lastHeartbeat,
      segmentDuration: options.segmentDuration
    }));
  }

  private async startFfmpegProcess(cameraId: string, options: RecordingOptions): Promise<void> {
    const { rtspUrl, segmentDuration, outputDir, enableEncryption, username, password } = options;
    const outputPath = path.join(outputDir, `${cameraId}_%03d.mp4`);
    const args = this.buildFfmpegArgs(rtspUrl, outputPath, segmentDuration, { username, password });
    
    logger.debug(`Starting FFmpeg with args: ${args.join(' ')}`);
    
    const process = spawn('ffmpeg', args, {
      stdio: ['pipe', 'pipe', 'pipe']
    });
    
    process.stdout?.on('data', (data) => {
      logger.debug(`[FFmpeg ${cameraId} stdout] ${data.toString().trim()}`);
    });
    
    process.stderr?.on('data', (data) => {
      const message = data.toString().trim();
      logger.debug(`[FFmpeg ${cameraId} stderr] ${message}`);
      
      if (message.includes('Connection to tcp://') && message.includes('failed')) {
        this.handleStreamError(cameraId, new Error(message));
      }
    });
    
    process.on('exit', (code, signal) => {
      logger.warn(`FFmpeg process for camera ${cameraId} exited with code ${code}, signal ${signal}`);
      this.recordings.delete(cameraId);
      
      if (code !== 0 && signal !== 'SIGTERM') {
        this.handleStreamError(cameraId, new Error(`FFmpeg process exited with code ${code}`));
      }
    });
    
    this.recordings.set(cameraId, {
      process,
      options,
      currentSegment: 0,
      lastHeartbeat: new Date(),
      reconnectAttempts: 0
    });
    
    this.setupSegmentHandling(cameraId, outputDir, enableEncryption);
  }

  private buildFfmpegArgs(
    rtspUrl: string,
    outputPath: string,
    segmentDuration: number,
    auth?: { username?: string; password?: string }
  ): string[] {
    const args = [
      '-rtsp_transport', 'tcp',
      '-timeout', '5000000',
      '-stimeout', '5000000',
      '-i', rtspUrl,
      '-c:v', 'copy',
      '-an',
      '-f', 'segment',
      '-segment_time', segmentDuration.toString(),
      '-segment_format', 'mp4',
      '-reset_timestamps', '1',
      '-strftime', '1',
      outputPath
    ];
    
    if (auth?.username && auth?.password) {
      const authUrl = new URL(rtspUrl);
      authUrl.username = auth.username;
      authUrl.password = auth.password;
      
      const inputIndex = args.indexOf('-i');
      if (inputIndex !== -1) {
        args[inputIndex + 1] = authUrl.toString();
      }
    }
    
    return args;
  }

  private setupSegmentHandling(cameraId: string, outputDir: string, enableEncryption: boolean): void {
    const watcher = fs.watch(outputDir, (eventType, filename) => {
      if (eventType === 'rename' && filename) {
        const filePath = path.join(outputDir, filename);
        
        fs.access(filePath, fs.constants.F_OK, async (err) => {
          if (err) return;
          
          fs.stat(filePath, async (err, stats) => {
            if (err || stats.size <= 1024) return;
            
            const recording = this.recordings.get(cameraId);
            if (!recording) return;
            
            recording.lastHeartbeat = new Date();
            recording.currentSegment++;
            
            const recordingInfo: RecordingInfo = {
              cameraId,
              startTime: new Date(),
              segmentPath: filePath,
              segmentNumber: recording.currentSegment,
              isEncrypted: false
            };
            
            if (enableEncryption) {
              try {
                const encryptedPath = await EncryptionService.encryptFile(filePath);
                recordingInfo.segmentPath = encryptedPath;
                recordingInfo.isEncrypted = true;
                await StorageService.deleteFile(filePath);
              } catch (error) {
                logger.error(`Failed to encrypt segment for camera ${cameraId}:`, error);
              }
            }
            
            this.emit('segmentComplete', recordingInfo);
          });
        });
      }
    });
    
    this.once(`recordingStopped:${cameraId}`, () => {
      watcher.close();
    });
  }

  private async handleStreamError(cameraId: string, error: Error): Promise<void> {
    const recording = this.recordings.get(cameraId);
    if (!recording) return;
    
    recording.reconnectAttempts++;
    
    if (recording.reconnectAttempts > this.MAX_RECONNECT_ATTEMPTS) {
      logger.error(`Max reconnection attempts (${this.MAX_RECONNECT_ATTEMPTS}) reached for camera ${cameraId}`);
      this.emit('recordingError', { cameraId, error: 'Max reconnection attempts reached' });
      this.recordings.delete(cameraId);
      return;
    }
    
    logger.warn(`Attempting to reconnect to camera ${cameraId} (attempt ${recording.reconnectAttempts}/${this.MAX_RECONNECT_ATTEMPTS})`);
    
    setTimeout(() => {
      if (this.recordings.has(cameraId)) {
        this.startFfmpegProcess(cameraId, recording.options);
      }
    }, this.RECONNECT_DELAY_MS);
  }
}

export const recordingService = RecordingService.getInstance();
