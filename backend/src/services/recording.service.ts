import { spawn, ChildProcess, execSync, exec } from 'child_process';
import { EventEmitter } from 'events';
import fs from 'fs';
import path from 'path';
import { promisify } from 'util';
import { logger } from '../utils/logger';
import { StorageService } from './storage.service';
import { EncryptionService } from './encryption.service';

// Promisify common functions
const stat = promisify(fs.stat);
const readdir = promisify(fs.readdir);
const unlink = promisify(fs.unlink);
const writeFile = promisify(fs.writeFile);
const readFile = promisify(fs.readFile);
const execPromise = promisify(exec);
const setTimeoutPromise = promisify(setTimeout);
const fsStat = promisify(fs.stat);
const fsUnlink = promisify(fs.unlink);
const fsRename = promisify(fs.rename);

interface RecordingOptions {
  cameraId: string;
  rtspUrl: string;
  segmentDuration: number; // in seconds
  outputDir: string;
  enableEncryption: boolean;
  username?: string;
  password?: string;
  maxReconnectAttempts?: number;
  reconnectDelayMs?: number;
  healthCheckIntervalMs?: number;
  maxSegmentSizeMB?: number;
}

export interface RecordingInfo {
  cameraId: string;
  startTime: Date;
  segmentPath: string;
  segmentNumber: number;
  isEncrypted: boolean;
  sizeBytes: number;
  durationMs: number;
  bitrateKbps: number;
}

interface RecordingProcess {
  process: ChildProcess;
  options: RecordingOptions;
  currentSegment: number;
  lastHeartbeat: Date;
  reconnectAttempts: number;
  isHealthy: boolean;
  lastSegmentTime: Date;
  healthCheckInterval?: NodeJS.Timeout;
  watcher?: fs.FSWatcher;
  activeSegments: Set<string>;
  lastError?: Error;
  lastErrorTime?: Date;
  lastErrorType?: string;
  lastReconnectAttempt?: Date;
  nextReconnectDelay: number;
  lastActiveTime: Date;
  stats: {
    segmentsRecorded: number;
    segmentsUploaded: number;
    segmentsFailed: number;
    bytesRecorded: number;
    reconnectCount: number;
    totalUptimeMs: number;
    totalDowntimeMs: number;
    lastError?: string;
    lastErrorTime?: Date;
    ffmpegRestarts: number;
    lastRestartTime?: Date;
  };
  startTime: Date;
}

export class RecordingService extends EventEmitter {
  private static instance: RecordingService;
  private recordings: Map<string, RecordingProcess> = new Map();
  
  // Default configuration values
  private readonly DEFAULT_CONFIG = {
    MAX_RECONNECT_ATTEMPTS: 10,
    INITIAL_RECONNECT_DELAY_MS: 1000, // 1 second
    MAX_RECONNECT_DELAY_MS: 60000,    // 1 minute
    HEALTH_CHECK_INTERVAL_MS: 30000,   // 30 seconds
    MAX_SEGMENT_SIZE_MB: 500,          // 500MB
    SEGMENT_TIMEOUT_MULTIPLIER: 1.5,   // 1.5x segment duration
  };
  
  private readonly ffmpegPath: string;
  private isShuttingDown = false;

  private constructor() {
    super();
    
    // Find FFmpeg binary path
    try {
      this.ffmpegPath = process.env.FFMPEG_PATH || this.findFfmpegPath();
      logger.info(`Recording service initialized with FFmpeg at: ${this.ffmpegPath}`);
      
      // Set up graceful shutdown
      this.setupGracefulShutdown();
    } catch (error) {
      logger.error('Failed to initialize recording service:', error);
      throw error;
    }
  }
  
  private findFfmpegPath(): string {
    try {
      // Try to find FFmpeg in the system path
      const isWindows = process.platform === 'win32';
      const cmd = isWindows ? 'where ffmpeg' : 'which ffmpeg';
      const result = execSync(cmd).toString().trim();
      
      if (result && !result.includes('not found')) {
        return result.split('\n')[0].trim();
      }
      
      throw new Error('FFmpeg not found in system PATH');
    } catch (error) {
      logger.error('FFmpeg not found. Please install FFmpeg and ensure it\'s in your PATH.');
      throw new Error('FFmpeg is required for video recording');
    }
  }
  
  private setupGracefulShutdown(): void {
    const shutdownSignals = ['SIGINT', 'SIGTERM', 'SIGQUIT'];
    
    shutdownSignals.forEach(signal => {
      process.on(signal, async () => {
        if (this.isShuttingDown) return;
        this.isShuttingDown = true;
        
        logger.info(`Received ${signal}, shutting down recording service gracefully...`);
        
        // Stop all recordings
        const cameraIds = Array.from(this.recordings.keys());
        await Promise.all(cameraIds.map(id => this.stopRecording(id)));
        
        logger.info('Recording service shutdown complete');
        process.exit(0);
      });
    });
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
      // Create directory if it doesn't exist
      await fs.promises.mkdir(options.outputDir, { recursive: true });
      await this.startFfmpegProcess(cameraId, options);
      logger.info(`Recording started for camera ${cameraId}`);
    } catch (error: unknown) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      logger.error(`Failed to start recording for camera ${cameraId}: ${errorMessage}`);
      throw new Error(`Failed to start recording: ${errorMessage}`);
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
    } catch (error: unknown) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      logger.error(`Error stopping recording for camera ${cameraId}:`, errorMessage);
      throw new Error(`Failed to stop recording: ${errorMessage}`);
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
    
    logger.info(`Starting FFmpeg for camera ${cameraId}`, { rtspUrl });
    logger.debug(`FFmpeg command: ffmpeg ${args.join(' ')}`);
    
    const process = spawn(this.ffmpegPath, args, {
      stdio: ['pipe', 'pipe', 'pipe'],
      detached: false
    });
    
    // Create or update the recording process
    const now = new Date();
    const existingRecording = this.recordings.get(cameraId);
    const recording: RecordingProcess = existingRecording || {
      process,
      options,
      currentSegment: 0,
      lastHeartbeat: now,
      lastActiveTime: now,
      startTime: now,
      reconnectAttempts: 0,
      nextReconnectDelay: this.DEFAULT_CONFIG.INITIAL_RECONNECT_DELAY_MS,
      isHealthy: true,
      lastSegmentTime: now,
      activeSegments: new Set(),
      stats: {
        segmentsRecorded: 0,
        segmentsUploaded: 0,
        segmentsFailed: 0,
        bytesRecorded: 0,
        reconnectCount: 0,
        totalUptimeMs: 0,
        totalDowntimeMs: 0,
        ffmpegRestarts: 0
      }
    };
    
    // Update the process reference
    recording.process = process;
    recording.lastHeartbeat = now;
    recording.isHealthy = true;
    recording.stats.ffmpegRestarts = (recording.stats.ffmpegRestarts || 0) + 1;
    recording.stats.lastRestartTime = now;
    
    // Set up process event handlers
    process.stdout?.on('data', (data: Buffer) => {
      const message = data.toString().trim();
      if (message) {
        logger.debug(`[FFmpeg ${cameraId} stdout] ${message}`);
        
        // Update last activity timestamp on any output
        recording.lastActiveTime = new Date();
        recording.lastHeartbeat = new Date();
      }
    });
    
    process.stderr?.on('data', (data: Buffer) => {
      const message = data.toString().trim();
      if (!message) return;
      
      // Log non-critical FFmpeg messages at debug level
      if (message.includes('frame=') || message.includes('time=')) {
        logger.silly(`[FFmpeg ${cameraId} progress] ${message}`);
      } else {
        logger.debug(`[FFmpeg ${cameraId} stderr] ${message}`);
      }
      
      // Check for common error patterns
      const errorPatterns = [
        { pattern: 'Connection to tcp://', error: 'RTSP connection failed' },
        { pattern: 'Connection refused', error: 'Connection refused' },
        { pattern: 'No route to host', error: 'No route to host' },
        { pattern: 'Connection timed out', error: 'Connection timed out' },
        { pattern: 'Server returned 404 Not Found', error: 'RTSP endpoint not found (404)' },
        { pattern: '401 Unauthorized', error: 'Authentication failed (401)' }
      ];
      
      // Check for errors in the message
      const matchedError = errorPatterns.find(p => message.includes(p.pattern));
      if (matchedError) {
        logger.warn(`[FFmpeg ${cameraId} error] ${matchedError.error}`);
        this.handleStreamError(cameraId, new Error(matchedError.error));
      }
    });

    process.on('close', (code: number | null, signal: NodeJS.Signals | null) => {
      const exitInfo = {
        code,
        signal,
        uptime: Date.now() - recording.startTime.getTime(),
        segmentsRecorded: recording.stats.segmentsRecorded
      };
      
      if (code === 0 || signal === 'SIGTERM') {
        logger.info(`FFmpeg process for camera ${cameraId} exited normally`, exitInfo);
      } else {
        logger.warn(`FFmpeg process for camera ${cameraId} exited unexpectedly`, exitInfo);
        // Only handle as error if we're not already in a reconnection attempt
        if (recording.reconnectAttempts === 0) {
          this.handleStreamError(cameraId, new Error(`Process exited with code ${code} and signal ${signal}`));
        }
      }
    });
    
    // Store the recording process
    this.recordings.set(cameraId, recording);
    
    // Set up health checking if not already done
    if (!recording.healthCheckInterval) {
      this.setupHealthChecks(cameraId);
    }
    
    // Set up segment handling
    this.setupSegmentHandling(cameraId, outputDir, enableEncryption);
    
    logger.info(`FFmpeg process started for camera ${cameraId} (PID: ${process.pid})`);
  }
  
  private setupHealthChecks(cameraId: string): void {
    const recording = this.recordings.get(cameraId);
    if (!recording || recording.healthCheckInterval) return;

    // Función para verificar el estado de la cámara
    const checkCameraStatus = async () => {
      if (!recording) return;
      
      try {
        const now = new Date();
        const timeSinceLastHeartbeat = now.getTime() - recording.lastHeartbeat.getTime();
        const timeSinceLastSegment = now.getTime() - recording.lastSegmentTime.getTime();
        const segmentTimeout = recording.options.segmentDuration * 2000; // 2x segment duration in ms
        const segmentGenerationTimeout = recording.options.segmentDuration * 3000; // 3x segment duration
        
        // Verificar si el proceso sigue en ejecución
        const isProcessAlive = recording.process.exitCode === null && !recording.process.killed;
        
        if (!isProcessAlive) {
          logger.warn(`FFmpeg process for camera ${cameraId} is not running (exit code: ${recording.process.exitCode})`);
          throw new Error('FFmpeg process terminated unexpectedly');
        }
        
        // Verificar timeout de latido
        if (timeSinceLastHeartbeat > segmentTimeout) {
          throw new Error(`No heartbeat from FFmpeg in ${timeSinceLastHeartbeat}ms`);
        }
        
        // Verificar generación de segmentos
        if (timeSinceLastSegment > segmentGenerationTimeout) {
          throw new Error(`No new segments generated in ${timeSinceLastSegment}ms`);
        }
        
        // Actualizar métricas de estado
        recording.stats.totalUptimeMs += this.DEFAULT_CONFIG.HEALTH_CHECK_INTERVAL_MS;
        recording.isHealthy = true;
        
        // Registrar estado cada 10 segmentos o cada minuto (lo que ocurra primero)
        if (recording.stats.segmentsRecorded % 10 === 0 || 
            recording.stats.totalUptimeMs % 60000 < this.DEFAULT_CONFIG.HEALTH_CHECK_INTERVAL_MS) {
          logger.info(`Camera ${cameraId} health check OK`, {
            segmentsRecorded: recording.stats.segmentsRecorded,
            segmentsUploaded: recording.stats.segmentsUploaded,
            segmentsFailed: recording.stats.segmentsFailed,
            uptime: Math.floor(recording.stats.totalUptimeMs / 1000) + 's',
            lastSegmentTime: recording.lastSegmentTime.toISOString(),
            activeSegments: recording.activeSegments.size,
            memoryUsage: process.memoryUsage().rss / (1024 * 1024) + ' MB'
          });
        }
        
        // Verificar el uso de recursos
        this.checkResourceUsage(recording);
        
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        logger.error(`Health check failed for camera ${cameraId}: ${errorMessage}`);
        
        // Actualizar estado y métricas
        if (recording) {
          recording.isHealthy = false;
          recording.stats.lastError = errorMessage;
          recording.stats.lastErrorTime = new Date();
          
          // Manejar el error según su tipo
          this.handleHealthCheckError(cameraId, error);
        }
      }
    };
    
    // Ejecutar la verificación inmediatamente y luego en intervalos regulares
    checkCameraStatus();
    recording.healthCheckInterval = setInterval(
      checkCameraStatus, 
      this.DEFAULT_CONFIG.HEALTH_CHECK_INTERVAL_MS
    );
    
    // Limpiar el intervalo cuando se detenga la grabación
    this.once(`recordingStopped:${cameraId}`, () => {
      if (recording.healthCheckInterval) {
        clearInterval(recording.healthCheckInterval);
        recording.healthCheckInterval = undefined;
      }
    });
  }
  
  /**
   * Maneja errores específicos de las comprobaciones de salud
   */
  private handleHealthCheckError(cameraId: string, error: unknown): void {
    const recording = this.recordings.get(cameraId);
    if (!recording) return;
    
    const errorMessage = error instanceof Error ? error.message : String(error);
    
    // Intentar reiniciar la grabación para errores recuperables
    if (this.isRecoverableError(errorMessage)) {
      logger.warn(`Attempting to recover camera ${cameraId} from error: ${errorMessage}`);
      this.restartRecording(cameraId).catch(err => {
        logger.error(`Failed to restart camera ${cameraId}:`, err);
      });
    } else {
      // Para errores no recuperables, detener la grabación
      logger.error(`Unrecoverable error for camera ${cameraId}: ${errorMessage}`);
      this.stopRecording(cameraId).catch(err => {
        logger.error(`Error while stopping camera ${cameraId}:`, err);
      });
      
      // Notificar a los suscriptores
      this.emit('recordingError', {
        cameraId,
        error: errorMessage,
        timestamp: new Date(),
        canRetry: false
      });
    }
  }
  
  /**
   * Determina si un error es recuperable
   */
  private isRecoverableError(errorMessage: string): boolean {
    const recoverableErrors = [
      'FFmpeg process terminated',
      'No heartbeat',
      'No new segments',
      'Connection reset',
      'ETIMEDOUT',
      'ECONNRESET',
      'ENOTFOUND',
      'EAI_AGAIN'
    ];
    
    return recoverableErrors.some(pattern => errorMessage.includes(pattern));
  }
  
  /**
   * Verifica el uso de recursos del sistema
   */
  private checkResourceUsage(recording: RecordingProcess): void {
    try {
      const memoryUsage = process.memoryUsage();
      const memoryUsageMB = memoryUsage.rss / (1024 * 1024);
      const memoryThreshold = 500; // 500MB
      
      // Registrar advertencia si el uso de memoria es alto
      if (memoryUsageMB > memoryThreshold) {
        logger.warn(`High memory usage: ${memoryUsageMB.toFixed(2)}MB`, {
          cameraId: recording.options.cameraId,
          heapUsed: (memoryUsage.heapUsed / (1024 * 1024)).toFixed(2) + 'MB',
          heapTotal: (memoryUsage.heapTotal / (1024 * 1024)).toFixed(2) + 'MB',
          external: (memoryUsage.external / (1024 * 1024)).toFixed(2) + 'MB',
          arrayBuffers: (memoryUsage.arrayBuffers / (1024 * 1024)).toFixed(2) + 'MB'
        });
      }
      
      // Forzar recolección de basura si es necesario
      if (memoryUsageMB > memoryThreshold * 0.8) {
        if (global.gc) {
          global.gc();
          logger.debug('Garbage collection forced due to high memory usage');
        }
      }
      
    } catch (error) {
      logger.error('Error checking resource usage:', error);
    }
  }
  
  /**
   * Reinicia la grabación para una cámara
   */
  private async restartRecording(cameraId: string): Promise<void> {
    const recording = this.recordings.get(cameraId);
    if (!recording) {
      throw new Error(`No active recording found for camera ${cameraId}`);
    }
    
    logger.info(`Restarting recording for camera ${cameraId}...`);
    
    try {
      // Detener la grabación actual
      await this.stopRecording(cameraId);
      
      // Pequeño retraso antes de reiniciar
      await new Promise(resolve => setTimeout(resolve, 1000));
      
      // Iniciar una nueva grabación
      await this.startFfmpegProcess(cameraId, recording.options);
      
      logger.info(`Successfully restarted recording for camera ${cameraId}`);
      
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      logger.error(`Failed to restart recording for camera ${cameraId}:`, errorMessage);
      
      // Re-lanzar el error para manejo adicional
      throw error;
    }
  }

  private setupSegmentHandling(cameraId: string, outputDir: string, enableEncryption: boolean): void {
    const recording = this.recordings.get(cameraId);
    if (!recording) return;
    
    // Create a map to track files being processed
    const processingSegments = new Map<string, boolean>();
    
    // Configurar el observador del directorio
    const watcher = fs.watch(outputDir, async (eventType: string, filename: string | null) => {
      if (eventType !== 'rename' || !filename || !filename.endsWith('.mp4')) {
        return;
      }
      
      const filePath = path.join(outputDir, filename);
      
      // Evitar procesamiento duplicado
      if (processingSegments.has(filePath)) {
        return;
      }
      
      try {
        // Marcar el archivo como en proceso
        processingSegments.set(filePath, true);
        
        // Esperar un breve momento para asegurar que el archivo esté completamente escrito
        await new Promise(resolve => setTimeout(resolve, 100));
        
        // Verificar que el archivo exista y tenga tamaño válido
        const stats = await fs.promises.stat(filePath).catch(() => null);
        if (!stats || stats.size < 1024) {
          return;
        }
        
        // Actualizar el estado de la grabación
        recording.lastHeartbeat = new Date();
        recording.lastSegmentTime = new Date();
        recording.currentSegment++;
        recording.stats.segmentsRecorded++;
        
        // Calcular la duración y bitrate reales
        const durationMs = recording.options.segmentDuration * 1000;
        const bitrateKbps = Math.floor((stats.size * 8) / (recording.options.segmentDuration));
        
        const recordingInfo: RecordingInfo = {
          cameraId,
          startTime: new Date(Date.now() - durationMs), // Tiempo estimado de inicio
          segmentPath: filePath,
          segmentNumber: recording.currentSegment,
          isEncrypted: false,
          sizeBytes: stats.size,
          durationMs,
          bitrateKbps
        };
        
        // Manejar la encriptación si está habilitada
        if (enableEncryption) {
          try {
            // Usar el método optimizado para archivos grandes
            const encryptedPath = await EncryptionService.encryptVideoFile(
              filePath,
              `${filePath}.enc`
            );
            
            // Actualizar la información del segmento
            recordingInfo.segmentPath = encryptedPath;
            recordingInfo.isEncrypted = true;
            
            // Eliminar el archivo original después de la encriptación exitosa
            try {
              await fs.promises.unlink(filePath);
            } catch (error) {
              logger.warn(`Failed to delete original segment ${filePath}:`, error);
            }
            
            logger.debug(`Encrypted segment ${filename} (${(stats.size / (1024 * 1024)).toFixed(2)}MB)`);
            
          } catch (error) {
            const errorMessage = error instanceof Error ? error.message : String(error);
            logger.error(`Failed to encrypt segment ${filename}: ${errorMessage}`);
            
            // Actualizar estadísticas de error
            recording.stats.segmentsFailed++;
            
            // Emitir evento de error para manejo externo
            this.emit('segmentError', {
              cameraId,
              segmentPath: filePath,
              error: errorMessage,
              timestamp: new Date()
            });
            
            // Continuar sin encriptación
            recordingInfo.isEncrypted = false;
          }
        }
        
        // Registrar el segmento completado
        recording.stats.bytesRecorded += stats.size;
        recording.activeSegments.add(recordingInfo.segmentPath);
        
        logger.info(`Segment recorded: ${filename} (${(stats.size / (1024 * 1024)).toFixed(2)}MB)`, {
          cameraId,
          segmentNumber: recordingInfo.segmentNumber,
          encrypted: recordingInfo.isEncrypted,
          bitrateKbps: recordingInfo.bitrateKbps
        });
        
        // Emitir evento de segmento completado
        this.emit('segmentComplete', recordingInfo);
        
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        logger.error(`Error processing segment ${filename}:`, errorMessage);
        
        // Emitir evento de error
        this.emit('segmentError', {
          cameraId,
          segmentPath: filePath,
          error: errorMessage,
          timestamp: new Date()
        });
        
      } finally {
        // Limpiar el seguimiento de procesamiento
        processingSegments.delete(filePath);
      }
    });
    
    // Limpiar recursos cuando se detenga la grabación
    // Clean up when recording is stopped
    this.once(`recordingStopped:${cameraId}`, () => {
      try {
        if (watcher) {
          watcher.close();
        }
        if (processingSegments) {
          processingSegments.clear();
        }
      } catch (error) {
        logger.error(`Error cleaning up segment handler for camera ${cameraId}:`, error);
      }
    });

    // Store the watcher in the recording object
    (recording as any).watcher = watcher;
  }

  private buildFfmpegArgs(
    rtspUrl: string,
    outputPath: string,
    segmentDuration: number,
    auth?: { username?: string; password?: string }
  ): string[] {
    const args: string[] = [
      '-rtsp_transport', 'tcp',  // Force TCP for better reliability
      '-timeout', '5000000',
      '-stimeout', '5000000'
    ];

    // Add authentication if both username and password are provided
    if (auth?.username && auth.password) {
      args.push('-user', auth.username, '-password', auth.password);
    }

    // Add input and output parameters
    args.push(
      '-i', rtspUrl,
      '-c:v', 'copy',            // Copy video stream without re-encoding
      '-c:a', 'aac',             // Encode audio to AAC
      '-f', 'segment',           // Output format
      '-segment_time', segmentDuration.toString(),
      '-segment_format', 'mp4',
      '-segment_clocktime_offset', '30',
      '-segment_clocktime_wrap_duration', '43200',
      '-movflags', 'frag_keyframe+empty_moov',
      '-frag_duration', '1000000',
      '-y',
      outputPath
    );

    return args;
  }

  private isAuthenticationError(error: unknown): boolean {
    const errorMessage = error instanceof Error ? error.message : String(error);
    return errorMessage.includes('401') || 
           errorMessage.includes('403') || 
           errorMessage.includes('unauthorized') || 
           errorMessage.includes('forbidden');
  }

  /**
   * Attempts to reconnect to a camera stream after a failure
   */
  private async reconnectCamera(cameraId: string): Promise<void> {
    const recording = this.recordings.get(cameraId);
    if (!recording) {
      logger.warn(`Cannot reconnect - no recording found for camera ${cameraId}`);
      return;
    }

    try {
      logger.info(`Attempting to reconnect to camera ${cameraId}...`);
      
      // Stop any existing process
      if (recording.process && !recording.process.killed) {
        await this.safeKillProcess(recording.process);
      }
      
      // Reset reconnection state
      recording.reconnectAttempts = 0;
      recording.nextReconnectDelay = 0;
      recording.isHealthy = true;
      
      logger.info(`Successfully reconnected to camera ${cameraId}`);
      this.emit('recordingReconnected', { cameraId, timestamp: new Date() });
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      logger.error(`Failed to reconnect to camera ${cameraId}: ${errorMessage}`);
      
      // Schedule another reconnection attempt
      await this.handleStreamError(cameraId, error);
    }
  }

  private async handleStreamError(cameraId: string, error: unknown): Promise<void> {
    const recording = this.recordings.get(cameraId);
    if (!recording) {
      logger.warn(`No active recording found for camera ${cameraId} when handling stream error`);
      return;
    }

    // Convert error to Error instance if it's not already one
    const errorObj = error instanceof Error ? error : new Error(String(error));
    
    // Update error state
    recording.lastError = errorObj;
    recording.lastErrorTime = new Date();
    recording.isHealthy = false;

    // Log the error
    logger.error(`Stream error for camera ${cameraId}:`, errorObj);

    // Check if this is an authentication error
    if (this.isAuthenticationError(errorObj)) {
      logger.error(`Authentication failed for camera ${cameraId}. Stopping recording.`);
      this.emit('recordingError', { 
        cameraId, 
        error: 'Authentication failed', 
        timestamp: new Date(),
        fatal: true
      });
      
      // Stop recording on authentication errors
      await this.stopRecording(cameraId);
      return;
    }

    // Check if we've exceeded max reconnection attempts
    const maxAttempts = recording.options.maxReconnectAttempts || this.DEFAULT_CONFIG.MAX_RECONNECT_ATTEMPTS;
    if (recording.reconnectAttempts >= maxAttempts) {
      logger.error(`Max reconnection attempts (${maxAttempts}) reached for camera ${cameraId}. Stopping recording.`);
      this.emit('recordingError', { 
        cameraId, 
        error: new Error(`Max reconnection attempts (${maxAttempts}) reached`),
        fatal: true 
      });
      await this.stopRecording(cameraId);
      return;
    }

    // Calculate next reconnection delay with exponential backoff and jitter
    const baseDelay = Math.min(
      this.DEFAULT_CONFIG.INITIAL_RECONNECT_DELAY_MS * Math.pow(2, recording.reconnectAttempts - 1),
      this.DEFAULT_CONFIG.MAX_RECONNECT_DELAY_MS
    );
    const jitter = Math.floor(Math.random() * baseDelay * 0.2); // Add up to 20% jitter
    const delay = baseDelay + jitter;
    
    logger.info(`Attempting to reconnect to camera ${cameraId} in ${delay}ms (attempt ${recording.reconnectAttempts}/${recording.options.maxReconnectAttempts || this.DEFAULT_CONFIG.MAX_RECONNECT_ATTEMPTS})`);
    
    // Schedule reconnection
    setTimeout(() => this.reconnectCamera(cameraId), delay).unref();
  }

  private getRecordingStats(recording: RecordingProcess | undefined): {
    totalUptime: number;
    totalDowntime: number;
    lastError: string | null;
    lastErrorTime: Date | null;
    isHealthy: boolean;
    reconnectAttempts: number;
    nextReconnectDelay: number;
    startTime: Date | null;
    lastErrorType: string | null;
  } {
    if (!recording) {
      return {
        totalUptime: 0,
        totalDowntime: 0,
        lastError: null,
        lastErrorTime: null,
        isHealthy: false,
        reconnectAttempts: 0,
        nextReconnectDelay: 0,
        startTime: null,
        lastErrorType: null
      };
    }

    const now = new Date();
    const lastError = recording.lastError ? 
      (typeof recording.lastError === 'string' ? recording.lastError : recording.lastError.message || 'Unknown error') : 
      null;
    const lastErrorTime = recording.lastErrorTime || null;
    const lastErrorType = recording.lastErrorType || null;
    const startTime = recording.startTime || null;
    
    // Calculate uptime and downtime
    const uptime = startTime ? now.getTime() - startTime.getTime() : 0;
    const downtime = lastErrorTime ? now.getTime() - lastErrorTime.getTime() : 0;

    return {
      totalUptime: uptime,
      totalDowntime: downtime,
      lastError,
      lastErrorTime,
      isHealthy: recording.isHealthy,
      reconnectAttempts: recording.reconnectAttempts,
      nextReconnectDelay: recording.nextReconnectDelay,
      startTime,
      lastErrorType
    };
  }

  private getRecordingUptime(recording: RecordingProcess | undefined): { totalUptime: number; totalDowntime: number } {
    if (!recording) {
      return {
        totalUptime: 0,
        totalDowntime: 0
      };
    }
    
    return {
      totalUptime: recording.stats?.totalUptimeMs || 0,
      totalDowntime: recording.stats?.totalDowntimeMs || 0
    };
  }

  private safeKillProcess(process: ChildProcess | undefined): void {
    if (!process || (process as any).killed) {
      return;
    }

    try {
      process.kill('SIGTERM');
      
      // Force kill if process doesn't exit after a short delay
      const forceKillTimer = setTimeout(() => {
        try {
          if (process && !(process as any).killed) {
            process.kill('SIGKILL');
          }
        } catch (error) {
          logger.warn('Error force killing process:', error);
        }
      }, 2000);
      
      // Don't block the event loop
      if ((forceKillTimer as any).unref) {
        (forceKillTimer as any).unref();
      }
    } catch (error) {
      logger.warn('Error killing process:', error);
    }
  }

  /**
   * Cleans up resources associated with a recording
   * @param recording - The recording process to clean up
   */
  private cleanupRecordingResources(recording: RecordingProcess | undefined): void {
    if (!recording) {
      return;
    }

    try {
      // Stop any running process
      if (recording.process && !(recording.process as any).killed) {
        this.safeKillProcess(recording.process);
      }

      // Clear any active health checks
      if (recording.healthCheckInterval) {
        clearInterval(recording.healthCheckInterval);
        delete (recording as any).healthCheckInterval;
      }

      // Close any active file watchers
      if ((recording as any).watcher) {
        try {
          (recording as any).watcher.close();
        } catch (error) {
          logger.warn('Error closing file watcher:', error);
        }
        delete (recording as any).watcher;
      }

      // Clean up any active segments
      if ((recording as any).activeSegments) {
        (recording as any).activeSegments.clear();
      }
      
      // Clear any pending timeouts
      if ((recording as any).reconnectTimeout) {
        clearTimeout((recording as any).reconnectTimeout);
        delete (recording as any).reconnectTimeout;
      }
    } catch (error) {
      logger.error('Error cleaning up recording resources:', error);
    }
  }
}

export const recordingService = RecordingService.getInstance();
