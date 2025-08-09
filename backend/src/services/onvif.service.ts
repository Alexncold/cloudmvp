import { EventEmitter } from 'events';
import * as onvif from 'node-onvif';
import { promisify } from 'util';
import { spawn } from 'child_process';
import { Camera } from '@prisma/client';
import { CameraConfigDatabase } from '../utils/camera-config-database';
import { EncryptionService } from './encryption.service';
import { logger } from '../utils/logger';
import type { 
  DiscoveredCamera, 
  RTSPUrlInfo, 
  ValidationResult, 
  CameraCapabilities, 
  SuggestedCredential,
  CameraDiscoveryOptions,
  CameraConnectionOptions,
  StreamType,
  AuthType,
  VideoCodec,
  HeartbeatResult
} from '@shared/types/onvif';

// Re-export types for backward compatibility
export type { 
  DiscoveredCamera, 
  RTSPUrlInfo, 
  ValidationResult, 
  CameraCapabilities, 
  SuggestedCredential,
  CameraDiscoveryOptions,
  CameraConnectionOptions,
  StreamType,
  AuthType,
  VideoCodec,
  HeartbeatResult 
} from '@shared/types/onvif';

type OnvifDevice = onvif.Device;

// Type definitions
interface DeviceInformation {
  manufacturer?: string;
  model?: string;
  firmwareVersion?: string;
  serialNumber?: string;
  hardwareId?: string;
}

interface SystemDateAndTime {
  UTCDateTime?: {
    date?: {
      year?: number;
      month?: number;
      day?: number;
    };
    time?: {
      hour?: number;
      minute?: number;
      second?: number;
    };
  };
  LocalDateTime?: {
    date?: {
      year?: number;
      month?: number;
      day?: number;
    };
    time?: {
      hour?: number;
      minute?: number;
      second?: number;
    };
  };
  Timezone?: string;
}

/**
 * Configuration for a camera manufacturer
 */
interface ManufacturerConfig {
  /** RTSP-specific configuration */
  rtsp?: {
    /** Common RTSP paths for this manufacturer */
    paths?: string[];
    /** Common RTSP ports for this manufacturer */
    ports?: number[];
    /** Common credentials for this manufacturer */
    credentials?: Array<{
      username: string;
      password: string;
      /** Authentication type (default: 'basic') */
      authType?: 'basic' | 'digest';
      /** Notes about these credentials */
      notes?: string;
    }>;
  };
  
  /** ONVIF service path (default: '/onvif/device_service') */
  onvifPath?: string;
  
  /** Default HTTP port (if different from 80) */
  httpPort?: number;
  
  /** Default RTSP port (if different from 554) */
  rtspPort?: number;
  
  /** Features supported by this manufacturer's cameras */
  features?: {
    /** Whether PTZ is supported */
    ptz?: boolean;
    /** Whether audio is supported */
    audio?: boolean;
    /** Whether motion detection is supported */
    motionDetection?: boolean;
    /** Additional vendor-specific features */
    [key: string]: boolean | string | number | undefined;
  };
  
  /** Additional manufacturer-specific configuration */
  [key: string]: any;
}

/**
 * Result of testing an RTSP URL
 */
interface RTSPUrlTestResult {
  /** The URL that was tested */
  url: string;
  /** Whether the test was successful */
  success: boolean;
  /** Error message if the test failed */
  error?: string;
  /** HTTP status code if available */
  statusCode?: number;
  /** Time taken for the test in milliseconds */
  duration?: number;
  /** Additional test metadata */
  metadata?: {
    /** Whether this URL requires authentication */
    requiresAuth?: boolean;
    /** Whether this URL is a snapshot URL */
    isSnapshot?: boolean;
    /** Any additional test results */
    [key: string]: any;
  };
}

export class ONVIFService extends EventEmitter {
  private onvifManager: typeof onvif = onvif;
  private configDatabase: CameraConfigDatabase;
  private encryptionService: EncryptionService;
  private discoveryCache: Map<string, DiscoveredCamera>;
  private pingCache: Map<string, { timestamp: number; result: boolean }>;
  private readonly PING_CACHE_TTL = 30000; // 30 segundos
  private logger = logger;

  constructor() {
    super();
    this.onvifManager = onvif;
    this.configDatabase = new CameraConfigDatabase();
    this.encryptionService = new EncryptionService();
    this.discoveryCache = new Map<string, DiscoveredCamera>();
    this.pingCache = new Map<string, { timestamp: number; result: boolean }>();
  }

  /**
   * Creates an ONVIF client for the specified camera
   */
  /**
   * Creates an ONVIF client for the specified camera
   */
  private async createOnvifClient(params: {
    ipAddress: string;
    port: number;
    username: string;
    password: string;
    manufacturer?: string;
  }): Promise<onvif.Device> {
    const { ipAddress, port = 80, username, password } = params;
    const xaddr = `http://${ipAddress}:${port}/onvif/device_service`;
    
    this.logger.debug(`Creating ONVIF client for ${xaddr}`, { 
      ipAddress,
      port,
      username: username ? '***' : 'none',
      hasPassword: !!password
    });
    
    try {
      // Type assertion needed because node-onvif types are incomplete
      const device = new this.onvifManager.Device({
        xaddr,
        user: username,
        pass: password,
      }) as onvif.Device;
      
      await device.init();
      this.logger.debug(`Successfully initialized ONVIF client for ${ipAddress}`);
      return device;
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      this.logger.error(`Failed to create ONVIF client for ${ipAddress}:`, errorMessage);
      
      // Enhance the error with more context
      const enhancedError = new Error(`Failed to connect to ONVIF device at ${ipAddress}: ${errorMessage}`);
      if (error instanceof Error) {
        enhancedError.stack = error.stack;
      }
      
      throw enhancedError;
    }
  }

  /**
   * Normalizes the manufacturer name for consistent comparison
   * @param manufacturer The raw manufacturer name to normalize
   * @returns A normalized manufacturer identifier
   */
  private normalizeManufacturer(manufacturer: string): string {
    if (!manufacturer) return 'generic';
    
    const lower = manufacturer.trim().toLowerCase();
    
    // First try to match known manufacturers
    if (lower.includes('hikvision')) return 'hikvision';
    if (lower.includes('dahua')) return 'dahua';
    if (lower.includes('axis')) return 'axis';
    
    // If no specific match, return the normalized string or 'generic' if empty
    return lower || 'generic';
  }

  /**
   * Determines the stream type based on the path
   * @param path The path or URL to analyze
   * @returns The determined stream type ('main', 'sub', or 'mobile')
   */
  private determineStreamType(path: string): 'main' | 'sub' | 'mobile' {
    const lowerPath = path.toLowerCase();
    
    // Check for sub stream indicators
    if (lowerPath.includes('sub') || lowerPath.includes('low') || 
        lowerPath.includes('secondary') || lowerPath.includes('102')) {
      return 'sub';
    }
    
    // Check for mobile stream indicators
    if (lowerPath.includes('mobile') || lowerPath.includes('mob') || 
        lowerPath.includes('m ') || lowerPath.endsWith('/m') || 
        lowerPath.includes('103')) {
      return 'mobile';
    }
    
    // Default to main stream
    return 'main';
  }

  /**
   * Extracts resolution from path if available
   */
  private extractResolutionFromPath(path: string): string {
    const resolutionMatch = path.match(/(\d+x\d+)/);
    return resolutionMatch ? resolutionMatch[0] : 'unknown';
  }

  /**
   * Extracts available resolutions from device capabilities
   */
  private extractResolutions(capabilities: any): string[] {
    if (!capabilities || !capabilities.media || !capabilities.media.encoding) return [];
    return capabilities.media.encoding.resolutions || [];
  }

  /**
   * Tests connection to an RTSP stream
   */
  /**
   * Tests connection to an RTSP stream using ffprobe
   * @param rtspUrl The RTSP URL to test
   * @param timeoutMs Timeout in milliseconds (default: 10000)
   * @returns Promise<boolean> True if the stream is valid, false otherwise
   */
  private async testRTSPConnection(rtspUrl: string, timeoutMs: number = 10000): Promise<boolean> {
    return new Promise<boolean>((resolve) => {
      type FFProbeResult = {
        streams?: Array<{
          codec_name?: string;
          width?: number;
          height?: number;
          [key: string]: unknown;
        }>;
      };

      let ffprobe: ReturnType<typeof spawn> | null = null;
      let timeout: NodeJS.Timeout | null = null;
      let output = '';
      let errorOutput = '';

      const cleanup = (): void => {
        // Clear timeout if it exists
        if (timeout !== null) {
          clearTimeout(timeout);
          timeout = null;
        }

        // Clean up ffprobe process if it exists
        if (ffprobe !== null) {
          // Remove all event listeners to prevent memory leaks
          ffprobe.stdout?.removeAllListeners('data');
          ffprobe.stderr?.removeAllListeners('data');
          ffprobe.removeAllListeners('close');
          ffprobe.removeAllListeners('error');

          // Kill the process if it's still running
          if (!ffprobe.killed) {
            try {
              ffprobe.kill('SIGKILL');
            } catch (error) {
              this.logger.debug('Error killing ffprobe process', {
                error: error instanceof Error ? error.message : String(error),
                rtspUrl
              });
            }
          }
          ffprobe = null;
        }
      };

      const onTimeout = (): void => {
        this.logger.debug('FFprobe timed out', { rtspUrl, timeoutMs });
        cleanup();
        resolve(false);
      };

      const onError = (error: Error): void => {
        this.logger.debug('FFprobe process error', { 
          error: error.message,
          rtspUrl 
        });
        cleanup();
        resolve(false);
      };

      try {
        // Spawn ffprobe process with appropriate arguments
        ffprobe = spawn('ffprobe', [
          '-v', 'error',
          '-select_streams', 'v:0',
          '-show_entries', 'stream=codec_name,width,height',
          '-of', 'json',
          rtspUrl
        ], {
          stdio: ['ignore', 'pipe', 'pipe']
        });

        // Handle stdout data
        ffprobe.stdout?.on('data', (data: Buffer): void => {
          output += data.toString('utf8');
        });

        // Handle stderr data
        ffprobe.stderr?.on('data', (data: Buffer): void => {
          errorOutput += data.toString('utf8');
        });

        // Handle process close event
        ffprobe.on('close', (code: number | null): void => {
          cleanup();
          
          if (code === 0) {
            try {
              // Parse ffprobe output
              const result: FFProbeResult = JSON.parse(output);
              const hasValidStreams = Array.isArray(result.streams) && 
                result.streams.length > 0 &&
                result.streams.some(stream => 
                  stream.codec_name && 
                  stream.width && 
                  stream.height
                );
              
              if (!hasValidStreams) {
                this.logger.debug('No valid video streams found in ffprobe output', { 
                  rtspUrl,
                  output,
                  errorOutput
                });
              }
              resolve(hasValidStreams);
            } catch (error) {
              this.logger.debug('Failed to parse ffprobe output', { 
                error: error instanceof Error ? error.message : String(error),
                output,
                errorOutput,
                rtspUrl
              });
              resolve(false);
            }
          } else {
            this.logger.debug('FFprobe process failed', { 
              code,
              error: errorOutput || 'No error output',
              rtspUrl 
            });
            resolve(false);
          }
        });

        // Handle process errors
        ffprobe.on('error', onError);
        
        // Set timeout for the ffprobe process
        timeout = setTimeout(onTimeout, timeoutMs);
      } catch (error) {
        this.logger.error({ message: 'Error in testRTSPConnection', data: { error: error instanceof Error ? error.message : String(error), rtspUrl } });
        cleanup();
        resolve(false);
      }
    });
  }

  /**
   * Pings a camera to check if it's online
   * @param ip The IP address to ping
   * @returns Promise that resolves to true if the ping was successful, false otherwise
   */
  private async pingCamera(ip: string): Promise<boolean> {
    const cacheKey = `ping_${ip}`;
    const cached = this.pingCache.get(cacheKey);
    
    // Return cached result if still valid
    if (cached && (Date.now() - cached.timestamp) < this.PING_CACHE_TTL) {
      return cached.result;
    }
    
    const isWindows = process.platform === 'win32';
    const pingCmd = isWindows ? 'ping' : 'ping';
    const pingArgs = isWindows 
      ? ['-n', '1', '-w', '2000', ip] 
      : ['-c', '1', '-W', '2', ip];
    
    return new Promise((resolve) => {
      const ping = spawn(pingCmd, pingArgs);
      
      ping.on('close', (code) => {
        const result = code === 0;
        this.pingCache.set(cacheKey, { timestamp: Date.now(), result });
        resolve(result);
      });
      
      // Timeout after 3 seconds
      setTimeout(() => {
        if (!ping.killed) {
          ping.kill();
          this.pingCache.set(cacheKey, { timestamp: Date.now(), result: false });
          resolve(false);
        }
      }, 3000);
    });
  }

  /**
   * Detects common credentials for camera authentication
   */
  private async detectCommonCredentials(ip: string, port: number): Promise<SuggestedCredential[]> {
    const testedUrl = `http://${ip}:${port}/onvif/device_service`;
    const commonCredentials = [
      { username: 'admin', password: 'admin', confidence: 0.9 },
      { username: 'admin', password: '12345', confidence: 0.8 },
      { username: 'admin', password: '123456', confidence: 0.7 },
      { username: 'admin', password: 'password', confidence: 0.6 },
      { username: 'admin', password: '', confidence: 0.5 },
      { username: 'admin', password: 'admin123', confidence: 0.7 },
      { username: 'root', password: 'root', confidence: 0.8 },
      { username: 'root', password: '12345', confidence: 0.7 },
      { username: 'root', password: 'admin', confidence: 0.6 },
      { username: 'service', password: 'service', confidence: 0.5 },
    ] as const;

    // Check if camera is reachable first
    const isReachable = await this.pingCamera(ip);
    if (!isReachable) {
      this.logger.warn({ message: `Camera at ${ip} is not reachable` });
      return [];
    }

    // Try each credential set
    const validCredentials: SuggestedCredential[] = [];
    
    for (const cred of commonCredentials) {
      try {
        const device = new this.onvifManager.Device({
          xaddr: testedUrl,
          user: cred.username,
          pass: cred.password,
        });
        
        await device.init();
        
        // Add the valid credential with required fields
        validCredentials.push({
          username: cred.username,
          password: cred.password,
          confidence: cred.confidence,
          testedUrl,
          authType: 'basic' as const, // Assume basic auth for now, could be updated based on actual auth type
        });
      } catch (error) {
        // Credential failed, try next one
        continue;
      }
    }

    return validCredentials;
  }

  /**
   * Detects camera capabilities
   */
  /**
   * Detects camera capabilities
   */
  private async detectCapabilities(device: onvif.Device, manufacturer?: string): Promise<CameraCapabilities> {
    // Map the detailed capabilities to the CameraCapabilities interface
    const mapToCameraCapabilities = (capabilities: {
      hasPTZ: boolean;
      hasAudio: boolean;
      hasMotionDetection: boolean;
      hasNightVision: boolean;
      hasInfrared: boolean;
      hasZoom: boolean;
      hasFocus: boolean;
      hasIris: boolean;
      hasPresets: boolean;
      hasEvents: boolean;
      hasAnalytics: boolean;
      resolutions: string[];
      codecs: string[];
      maxFrameRate: number;
      onvifVersion: string;
      profiles: any[];
      manufacturerFeatures: Record<string, boolean>;
    }): CameraCapabilities => {
      // Create base capabilities object with required fields
      const baseCapabilities: CameraCapabilities = {
        streaming: true, // Assume streaming is always true for ONVIF cameras
        ptz: capabilities.hasPTZ,
        audio: capabilities.hasAudio,
        motionDetection: capabilities.hasMotionDetection,
        analytics: capabilities.hasAnalytics,
        nightVision: capabilities.hasNightVision,
        events: capabilities.hasEvents,
        snapshots: true, // Most ONVIF cameras support snapshots
        recording: true, // Assume recording is supported
        onvifVersion: capabilities.onvifVersion || '1.0',
        maxFrameRate: capabilities.maxFrameRate || 30
      };
      
      // Add manufacturer features as additional properties
      // Only include boolean values to match the index signature
      Object.entries(capabilities.manufacturerFeatures || {}).forEach(([key, value]) => {
        if (typeof value === 'boolean') {
          baseCapabilities[`manufacturer_${key}`] = value;
        }
      });
      
      return baseCapabilities;
    };
    // Define the base capabilities with default values that match the CameraCapabilities interface
    const baseCapabilities: CameraCapabilities = {
      // Core capabilities - all required by the interface
      streaming: true, // Assume streaming is supported
      ptz: false,     // Will be updated based on device capabilities
      audio: false,   // Will be updated based on device capabilities
      motionDetection: false, // Will be updated based on device capabilities
      analytics: false, // Will be updated based on device capabilities
      nightVision: false, // Will be updated based on device capabilities
      events: false,   // Will be updated based on device capabilities
      snapshots: true,  // Assume snapshots are supported
      recording: true,  // Assume recording is supported
      
      // Additional capabilities as string/number values
      onvifVersion: '1.0', // Default version, will be updated
      maxFrameRate: 30,
      
      // Store complex data as JSON strings to avoid type conflicts
      _resolutions: JSON.stringify(['1920x1080', '1280x720']),
      _codecs: JSON.stringify(['H.264']),
      _profiles: '[]',
      // Manufacturer features as individual boolean properties
      manufacturer_isHikvision: false,
      manufacturer_isDahua: false,
      manufacturer_isAxis: false,
      manufacturer_isSony: false,
      manufacturer_isBosch: false,
    };

    try {
      // Get device capabilities
      const deviceCapabilities = await device.getCapabilities();
      
      // Set ONVIF version if available
      const deviceInfo = deviceCapabilities?.device;
      if (deviceInfo && 'XAddr' in deviceInfo) {
        baseCapabilities.onvifVersion = '2.0'; // Default to 2.0 if device responds
      }

      // Check for PTZ capabilities
      try {
        type PTZPosition = {
          x?: number;
          y?: number;
          z?: number;
          zoom?: number;
          focus?: number;
          iris?: number;
          pan?: number;
          tilt?: number;
          [key: string]: unknown;
        };

        interface PTZStatus {
          position?: PTZPosition;
          moveStatus?: {
            panTilt?: string;
            zoom?: string;
            [key: string]: unknown;
          };
          [key: string]: unknown;
        }

        let ptzStatus: PTZStatus = {};
        try {
          ptzStatus = await new Promise<PTZStatus>(async (resolve, _reject) => {
            try {
              // Safely get the first available profile token with a fallback
              const profileToken = (device as any).profiles?.[0]?.token || 'Profile_1';
              
              // Use the ptz service to get the status
              const ptzService = (device as any).services?.ptz;
              if (!ptzService) {
                resolve({});
                return;
              }
              
              // Try the node-onvif style with profile token
              if (typeof ptzService.getStatus === 'function') {
                try {
                  // First try with profile token if available
                  if (profileToken) {
                    const status = await ptzService.getStatus({ ProfileToken: profileToken });
                    resolve(status || {});
                    return;
                  }
                  // Fall back to no parameters if profile token not available
                  const status = await ptzService.getStatus();
                  resolve(status || {});
                } catch (statusError) {
                  this.logger.debug({
                    level: 'debug',
                    message: 'Failed to get PTZ status with getStatus',
                    data: { error: statusError instanceof Error ? statusError.message : String(statusError) }
                  });
                  // Continue to try GetStatus as fallback
                }
              }
              
              // Fall back to ONVIF standard style if available
              if (typeof ptzService.GetStatus === 'function' && profileToken) {
                try {
                  const status = await ptzService.GetStatus({ ProfileToken: profileToken });
                  resolve((status?.data as PTZStatus) || {});
                  return;
                } catch (getStatusError) {
                  this.logger.debug({
                    level: 'debug',
                    message: 'Failed to get PTZ status with GetStatus',
                    data: { error: getStatusError instanceof Error ? getStatusError.message : String(getStatusError) }
                  });
                }
              } else {
                resolve({});
              }
            } catch (err) {
              this.logger.debug({ message: 'PTZ status check failed', data: { error: err instanceof Error ? err.message : String(err) } });
              resolve({});
            }
          });
        } catch (error) {
          this.logger.debug({ message: 'Error getting PTZ status', data: { error: error instanceof Error ? error.message : String(error) } });
        }
        
        if (ptzStatus?.position) {
          baseCapabilities.ptz = true;
          const position = ptzStatus.position;
          
          // Check for specific PTZ capabilities
          baseCapabilities.manufacturer_hasZoom = 'zoom' in position;
          baseCapabilities.manufacturer_hasFocus = 'focus' in position;
          baseCapabilities.manufacturer_hasIris = 'iris' in position;
          
          // Check for presets
          try {
            const presets = await new Promise<any[]>(async (resolve) => {
              try {
                // According to node-onvif.d.ts, getPresets takes no arguments
                const data = await device.getPresets();
                resolve(Array.isArray(data) ? data : []);
              } catch (err) {
                this.logger.debug({ message: 'Error getting presets', data: { error: err instanceof Error ? err.message : String(err) } });
                resolve([]);
              }
            });
            baseCapabilities.manufacturer_hasPresets = Array.isArray(presets) && presets.length > 0;
          } catch (presetError) {
            this.logger.debug({ message: 'Presets not supported', data: { error: presetError instanceof Error ? presetError.message : String(presetError) } });
          }
        }
      } catch (error) {
        this.logger.debug({ message: 'PTZ capabilities not supported', data: { error: error instanceof Error ? error.message : String(error) } });
      }

      // Get profiles and check for audio
      try {
        // Usar la versión con promesas de getProfiles
        const profiles = await device.getProfiles().catch((err: Error) => {
          this.logger.debug({ message: 'Error getting profiles', data: { error: err.message } });
          return [];
        });
        
        // Store profiles as a JSON string to avoid type conflicts
        const profilesArray = Array.isArray(profiles) ? profiles : [];
        // Store profiles as a JSON string in a property that matches the interface
        baseCapabilities._profiles = JSON.stringify(profilesArray);
        
        if (profilesArray[0]) {
          const profile = profilesArray[0];
          
          // Check for audio support
          try {
            // Usar la versión con promesas de getAudioSources
            const audioSources = await device.getAudioSources().catch((err: Error) => {
              this.logger.debug({ message: 'Error getting audio sources', data: { error: err.message } });
              return [];
            });
            // Set audio capability based on available audio sources
            baseCapabilities.audio = Array.isArray(audioSources) && audioSources.length > 0;
          } catch (audioError) {
            this.logger.debug({ message: 'Audio sources not available', data: { error: audioError instanceof Error ? audioError.message : String(audioError) } });
          }
          
          // Extract video configuration
          if (profile.VideoEncoderConfiguration?.$?.token) {
            try {
              // Obtener el token de configuración de video
              const configToken = profile.VideoEncoderConfiguration.$.token;
              // Try both possible method signatures for getVideoEncoderConfiguration
              let videoConfig = null;
              try {
                // First try with the node-onvif style (string parameter)
                videoConfig = await (device as any).getVideoEncoderConfiguration(configToken);
              } catch (firstError) {
                try {
                  // If that fails, try the standard ONVIF style (options object)
                  videoConfig = await (device as any).getVideoEncoderConfiguration({ ConfigurationToken: configToken });
                } catch (secondError) {
                  this.logger.debug({ 
                    level: 'debug',
                    message: 'Error getting video encoder configuration', 
                    data: { 
                      firstError: firstError instanceof Error ? firstError.message : String(firstError),
                      secondError: secondError instanceof Error ? secondError.message : String(secondError)
                    } 
                  });
                  return null;
                }
              }
              
              if (videoConfig?.Resolution) {
                const width = videoConfig.Resolution.Width || 1920;
                const height = videoConfig.Resolution.Height || 1080;
                // Store resolutions as a JSON string in a property that matches the interface
                baseCapabilities._resolutions = JSON.stringify([`${width}x${height}`]);
              }
              
              if (videoConfig?.Encoding) {
                // Store codecs as a JSON string in a property that matches the interface
                baseCapabilities._codecs = JSON.stringify([videoConfig.Encoding]);
              }
              
              if (videoConfig?.RateControl?.FrameRateLimit) {
                const frameRate = Number(videoConfig.RateControl.FrameRateLimit) || 30;
                baseCapabilities.maxFrameRate = frameRate;
              }
            } catch (videoError) {
              this.logger.debug({ message: 'Failed to get video configuration', data: { error: videoError instanceof Error ? videoError.message : String(videoError) } });
            }
          }
        }
      } catch (error) {
        this.logger.debug({ message: 'Failed to get profiles', data: { error: error instanceof Error ? error.message : String(error) } });
      }

      // Check for motion detection and analytics
      try {
        interface AnalyticsConfiguration {
          AnalyticsEngineConfiguration?: {
            MotionRegionDetection?: any;
            [key: string]: any;
          };
          [key: string]: any;
        }

        const analytics = await new Promise<AnalyticsConfiguration[]>((resolve, reject) => {
          device.getAnalyticsConfigurations((err: Error | null, data?: any) => {
            if (err) {
              this.logger.debug({ message: 'Failed to get analytics configurations', data: { error: err.message } });
              resolve([]);
            } else {
              resolve(Array.isArray(data) ? data : []);
            }
          });
        });

        if (analytics.length > 0) {
          baseCapabilities.motionDetection = analytics.some(
            (config) => config?.AnalyticsEngineConfiguration?.MotionRegionDetection !== undefined
          );
          baseCapabilities.analytics = true;
        }
      } catch (error) {
        this.logger.debug({ message: 'Analytics not supported', data: { error: error instanceof Error ? error.message : String(error) } });
      }

      // Check for events
      try {
        const events = await promisify(device.getEventProperties).call(device);
        baseCapabilities.events = !!events;
      } catch (error) {
        // Events not supported
      }

      // Check for presets
      try {
        // Get profiles to check for presets
        const profiles = await device.getProfiles();
        if (Array.isArray(profiles) && profiles.length > 0) {
          // Try to get the first profile token - handle different response formats
          let profileToken: string | undefined;
          
          // Check for different possible profile token locations in the response
          if (profiles[0].$ && profiles[0].$.token) {
            profileToken = profiles[0].$.token;
          } else if (profiles[0].token) {
            profileToken = profiles[0].token;
          } else if (typeof profiles[0] === 'string') {
            profileToken = profiles[0];
          }
          
          if (profileToken) {
            try {
              const presets = await device.getPresets({ ProfileToken: profileToken });
              baseCapabilities.manufacturer_hasPresets = Array.isArray(presets) && presets.length > 0;
            } catch (presetError) {
              // Failed to get presets, but we still have a valid profile
              baseCapabilities.manufacturer_hasPresets = false;
              this.logger.debug({
                level: 'debug',
                message: 'Failed to get presets',
                data: { error: presetError instanceof Error ? presetError.message : String(presetError) }
              });
            }
          } else {
            baseCapabilities.manufacturer_hasPresets = false;
          }
        } else {
          baseCapabilities.manufacturer_hasPresets = false;
        }
      } catch (error) {
        // Presets not supported or error getting profiles
        baseCapabilities.manufacturer_hasPresets = false;
        this.logger.debug({ 
          level: 'debug',
          message: 'Presets not supported', 
          data: { error: error instanceof Error ? error.message : String(error) } 
        });
      }

      // Check for night vision and infrared
      try {
        interface VideoSource {
          $: {
            token: string;
            Framerate?: string;
            Resolution?: {
              Width: number;
              Height: number;
            };
            Imaging?: {
              Brightness?: number;
              ColorSaturation?: number;
              Contrast?: number;
              Sharpness?: number;
            };
            // Propiedades específicas del fabricante
            DayNight?: string;
            InfraredCutFilter?: string;
          };
        }

        let videoSources: VideoSource[] = [];
        try {
          // Use the Promise-based API directly
          const result = await device.getVideoSources();
          videoSources = Array.isArray(result) ? result : [];
        } catch (err) {
          this.logger.debug({ message: 'Error getting video sources', data: { error: err instanceof Error ? err.message : String(err) } });
          videoSources = [];
        }

        if (videoSources.length > 0 && videoSources[0].$) {
          const videoSource = videoSources[0].$;
          
          // Usar type assertion para acceder a propiedades específicas del fabricante
          baseCapabilities.nightVision = 'DayNight' in videoSource;
          baseCapabilities.manufacturer_hasInfrared = 'InfraredCutFilter' in videoSource;
          
          // Add manufacturer-specific features
          if (manufacturer) {
            const normalizedManufacturer = manufacturer.toLowerCase();
            // Set individual manufacturer feature flags instead of using an object
            const manufacturerFeatures = {
              isHikvision: normalizedManufacturer.includes('hikvision'),
              isDahua: normalizedManufacturer.includes('dahua'),
              isAxis: normalizedManufacturer.includes('axis'),
              isSony: normalizedManufacturer.includes('sony'),
              isBosch: normalizedManufacturer.includes('bosch')
            };
            
            // Set night vision based on manufacturer if not detected
            if (!baseCapabilities.nightVision) {
              baseCapabilities.nightVision = 
                normalizedManufacturer.includes('hikvision') || 
                normalizedManufacturer.includes('dahua');
            }
          }
        }
      } catch (error) {
        this.logger.debug({ message: 'Could not determine night vision/infrared capabilities', data: { error: error instanceof Error ? error.message : String(error) } });
      }
      
      return baseCapabilities;
    } catch (error) {
      this.logger.error({ message: 'Error detecting camera capabilities', data: { error: error instanceof Error ? error.message : String(error) } });
      return baseCapabilities;
    }
  }

  /**
   * Calculates confidence score for camera detection
   * @param deviceOrRtspUrls Either an ONVIF device or an array of RTSP URLs
   * @param rtspUrlsOrCredentials Either an array of RTSP URLs or an array of credentials
   * @param manufacturer Optional manufacturer name for scoring
   * @returns A confidence score between 0 and 1 or 0 and 100 depending on the input
   */
  private calculateConfidence(
    deviceOrRtspUrls: onvif.Device | RTSPUrlInfo[],
    rtspUrlsOrCredentials?: Array<RTSPUrlInfo | { confidence: number }>,
    manufacturer?: string
  ): number {
    // Peso para cada factor de confianza
    const WEIGHTS = {
      MANUFACTURER_KNOWN: 0.3,
      RTSP_URL_VALID: 0.4,
      CREDENTIALS_VALID: 0.3
    };

    let confidence = 0;

    // Handle the case where we're calculating confidence from device and RTSP URLs
    if ('hostname' in deviceOrRtspUrls) {
      const device = deviceOrRtspUrls as onvif.Device;
      const rtspUrls = rtspUrlsOrCredentials as RTSPUrlInfo[] || [];
      
      // Base confidence for ONVIF device
      confidence += 40;
      
      // Add confidence based on manufacturer
      if (manufacturer) {
        const normalizedManufacturer = this.normalizeManufacturer(manufacturer);
        if (this.configDatabase.getManufacturerConfig(normalizedManufacturer)) {
          confidence += 20; // Known manufacturer
        }
      }
      
      // Add confidence for each valid RTSP URL
      if (rtspUrls.length > 0) {
        confidence += Math.min(30, rtspUrls.length * 10);
      }
      
      // Cap at 100
      return Math.min(100, confidence);
    } else {
      // Handle the case where we're calculating confidence from RTSP URLs and credentials
      const rtspUrls = deviceOrRtspUrls as RTSPUrlInfo[];
      const credentials = (rtspUrlsOrCredentials || []) as Array<{ confidence: number }>;
      
      // Peso para cada factor de confianza
      const WEIGHTS = {
        MANUFACTURER_KNOWN: 0.3,
        RTSP_URL_VALID: 0.4,
        CREDENTIALS_VALID: 0.3
      };

      let score = 0;
      
      // Puntuar fabricante conocido
      if (manufacturer && manufacturer !== 'generic') {
        score += WEIGHTS.MANUFACTURER_KNOWN;
      }
      
      // Puntuar URLs RTSP válidas
      if (rtspUrls.length > 0) {
        const rtspScore = rtspUrls.reduce((sum, url) => sum + (url.confidence || 0), 0) / rtspUrls.length;
        score += rtspScore * WEIGHTS.RTSP_URL_VALID;
      }
      
      // Puntuar credenciales válidas
      if (credentials.length > 0) {
        const credScore = credentials.reduce((sum, cred) => sum + (cred.confidence || 0), 0) / credentials.length;
        score += credScore * WEIGHTS.CREDENTIALS_VALID;
      }
      
      // Asegurar que el resultado esté entre 0 y 1
      return Math.min(Math.max(score, 0), 1);
    }
  }

  /**
   * Descubre cámaras en la red local usando WS-Discovery
   */
  async discoverCameras(timeoutMs: number = 10000): Promise<DiscoveredCamera[]> {
    this.logger.info({ message: 'Iniciando descubrimiento de cámaras', data: { timeoutMs } });
    this.discoveryCache.clear();

    try {
      // Usar una promesa para manejar la detección de dispositivos
      const devices = await new Promise<onvif.Device[]>((resolve) => {
        const discoveredDevices: onvif.Device[] = [];
        const discovery = this.onvifManager.Discover;
        
        // Manejador para cuando se descubre un dispositivo
        const onDevice = (device: onvif.Device) => {
          discoveredDevices.push(device);
        };
        
        // Configurar el manejador de eventos
        discovery.on('device', onDevice);
        
        // Iniciar la búsqueda
        discovery.start();
        
        // Configurar el timeout
        // Store the timeout so we can clear it if needed
        const discoveryTimeout = setTimeout(async () => {
          try {
            // For the Discover class, we just need to call stop()
            // The event listener will be automatically cleaned up when the instance is garbage collected
            discovery.stop();
            
            // Close the socket if available
            if ('socket' in discovery && typeof (discovery as any).socket?.close === 'function') {
              (discovery as any).socket.close();
            }
            
            resolve(discoveredDevices);
          } catch (error) {
            this.logger.error({ message: 'Error during discovery cleanup', data: { error: error instanceof Error ? error.message : String(error) } });
            resolve(discoveredDevices); // Still resolve with what we have
          }
        }, timeoutMs);
        
        // Add error handling for the discovery process
        discovery.on('error', (error: Error) => {
          clearTimeout(discoveryTimeout);
          this.logger.error({ message: 'Discovery error', data: { error: error.message } });
          resolve(discoveredDevices); // Resolve with what we have so far
        });
      });
      
      this.logger.debug({ message: `Se encontraron ${devices.length} dispositivos` });
      
      // Procesar dispositivos en paralelo
      const discoveryPromises = devices.map(device => this.processDiscoveredDevice(device));
      const results = await Promise.allSettled(discoveryPromises);
      
      // Filtrar resultados exitosos
      const discoveredCameras = results
        .filter((result): result is PromiseFulfilledResult<DiscoveredCamera> => 
          result.status === 'fulfilled' && result.value !== null
        )
        .map(result => result.value);
      
      this.logger.info(`Descubrimiento completado. Se encontraron ${discoveredCameras.length} cámaras válidas`);
      
      return discoveredCameras;
    } catch (error) {
      this.logger.error({ message: 'Error durante el descubrimiento de cámaras', data: { error: error instanceof Error ? error.message : String(error) } });
      throw new Error(`Error al descubrir cámaras: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  /**
   * Procesa un dispositivo descubierto y extrae información relevante
   */
  private async processDiscoveredDevice(device: onvif.Device): Promise<DiscoveredCamera | null> {
    try {
      const deviceInfo = await this.getDeviceInfo(device);
      const normalizedManufacturer = this.normalizeManufacturer(deviceInfo.manufacturer);
      const config = this.configDatabase.getManufacturerConfig(normalizedManufacturer);
      
      // Detectar URLs RTSP
      const rtspUrls = await this.detectRTSPUrls(device, config);
      
      // Detectar credenciales comunes
      const suggestedCredentials = await this.detectCommonCredentials(device.hostname, device.port);
      
      // Detectar capacidades
      const capabilities = await this.detectCapabilities(device, normalizedManufacturer);
      
      const discoveredCamera: DiscoveredCamera = {
        ip: device.hostname,
        port: device.port || 80,
        manufacturer: normalizedManufacturer,
        model: deviceInfo.model,
        firmware: deviceInfo.firmware,
        onvifUrl: device.xaddr,
        rtspUrls,
        suggestedCredentials,
        capabilities,
        confidence: this.calculateConfidence(rtspUrls, suggestedCredentials, normalizedManufacturer),
        discoveredAt: new Date()
      };
      
      // Almacenar en caché
      this.discoveryCache.set(device.hostname, discoveredCamera);
      
      return discoveredCamera;
    } catch (error) {
      this.logger.warn({ message: 'Error al procesar dispositivo', data: { ip: device.hostname, error: error instanceof Error ? error.message : String(error) } });
      return null;
    }
  }

  /**
   * Valida la configuración de una cámara
   */
  async validateCameraConfiguration(
    ip: string,
    port: number,
    username: string,
    password: string,
    rtspPath?: string
  ): Promise<ValidationResult> {
    const result: ValidationResult = {
      valid: false,
      onvifSupport: false,
      rtspSupport: false,
      detectedRtspUrl: '',
      manufacturer: 'Unknown',
      model: 'Unknown',
      firmware: 'Unknown',
      confidence: 0,
      validatedAt: new Date()
    };

    try {
      // Probar conexión ONVIF
      const device = new onvif.Device({
        xaddr: `http://${ip}:${port}/onvif/device_service`,
        user: username,
        pass: password
      });
      
      // Inicializar el dispositivo
      await device.init();
      
      const deviceInfo = await this.getDeviceInfo(device);
      result.onvifSupport = true;
      result.manufacturer = deviceInfo.manufacturer;
      result.model = deviceInfo.model;
      result.firmware = deviceInfo.firmware;
      
      // Probar RTSP si se proporciona un path
      if (rtspPath) {
        const rtspUrl = `rtsp://${username}:${password}@${ip}:554${rtspPath}`;
        const rtspValid = await this.testRTSPConnection(rtspUrl);
        
        if (rtspValid) {
          result.rtspSupport = true;
          result.detectedRtspUrl = rtspUrl;
        }
      }
      
      result.valid = result.onvifSupport || result.rtspSupport;
      // Configurar URLs RTSP para cálculo de confianza
      const rtspUrls: RTSPUrlInfo[] = [];
      if (result.rtspSupport) {
        rtspUrls.push({
          url: result.detectedRtspUrl,
          streamType: 'main',
          resolution: 'auto-detect',
          confidence: 1,
          tested: true,
          source: 'user-provided' as const
        });
      }
      
      // Calcular confianza basada en URLs RTSP y credenciales
      result.confidence = this.calculateConfidence(
        rtspUrls,
        rtspUrls, // Usamos las mismas URLs como segundo argumento ya que el tipo lo permite
        result.manufacturer
      );
      
      // Si no hay soporte RTSP pero sí ONVIF, establecer una confianza base
      if (!result.rtspSupport && result.onvifSupport) {
        result.confidence = Math.max(result.confidence, 0.7); // Mínimo 70% de confianza si hay ONVIF
      }
      
      return result;
    } catch (error) {
      this.logger.warn({ message: 'Validación de cámara fallida', data: { ip, error: error instanceof Error ? error.message : String(error) } });
      
      if (!result.onvifSupport && !result.rtspSupport) {
        result.error = 'No se pudo conectar a la cámara con las credenciales proporcionadas';
      } else if (!result.rtspSupport) {
        result.error = 'No se pudo acceder al stream RTSP con la ruta proporcionada';
      }
      
      return result;
    }
  }



  /**
   * Performs a heartbeat check on a camera to verify its status
   * @param camera Camera configuration with optional encrypted password and manufacturer
   * @returns Heartbeat result with detailed status information
   */
  public async performHeartbeat(
    camera: Camera & { password_encrypted?: string; manufacturer?: string }
  ): Promise<HeartbeatResult> {
    // Initialize result with default values
    const result: HeartbeatResult = {
      cameraId: Number(camera.id), // Ensure cameraId is a number
      overall: false,
      ping: false,
      onvif: false,
      rtsp: false,
      timestamp: new Date(),
      details: {}
    };

    try {
      // 1. Check basic connectivity with ping
      result.ping = await this.pingCamera(camera.ipAddress);
      
      if (!result.ping) {
        this.logger.warn({ message: 'Camera not reachable by ping', data: { cameraId: camera.id } });
        result.details.pingError = 'Camera not reachable by ping';
        return result;
      }
      
      // 2. Check ONVIF service if credentials are available
      if (camera.username) {
        try {
          // Decrypt password if encrypted
          const password = camera.password_encrypted 
            ? await EncryptionService.decryptText(camera.password_encrypted) 
            : '';
            
          // Create ONVIF client
          const device = await this.createOnvifClient({
            ipAddress: camera.ipAddress,
            port: camera.port || 80,
            username: camera.username,
            password,
            manufacturer: camera.manufacturer
          });
          
          // Verify ONVIF is working by getting device info
          const deviceInfo = await this.getDeviceInfo(device);
          result.onvif = true;
          
          // Update device info in details
          result.details.deviceInfo = {
            manufacturer: deviceInfo.manufacturer,
            model: deviceInfo.model,
            firmware: deviceInfo.firmware,
            uptime: deviceInfo.uptime
          };
          
          // Store uptime in details if available
          if (deviceInfo.uptime) {
            result.details.uptime = deviceInfo.uptime;
          }
        } catch (error) {
          const errorMessage = error instanceof Error ? error.message : String(error);
          this.logger.warn({ message: 'ONVIF connection failed', data: { cameraId: camera.id, error: errorMessage } });
          result.details.onvifError = errorMessage;
        }
      }
      
      // 3. Check RTSP if URL is available
      if (camera.rtspUrl) {
        try {
          let rtspUrl = camera.rtspUrl;
          
          // Add authentication to RTSP URL if credentials are available
          if (camera.username) {
            const password = camera.password_encrypted 
              ? await EncryptionService.decryptText(camera.password_encrypted) 
              : '';
              
            rtspUrl = rtspUrl.replace(
              'rtsp://', 
              `rtsp://${camera.username}:${password}@`
            );
          }
          
          // Test RTSP connection
          result.rtsp = await this.testRTSPConnection(rtspUrl);
          
          if (!result.rtsp) {
            this.logger.warn({ message: 'RTSP connection failed', data: { cameraId: camera.id } });
            result.details.rtspError = 'RTSP connection failed';
          } else {
            // Add RTSP URL to details if connection was successful
            result.details.rtspUrls = [{
              url: rtspUrl,
              streamType: 'main' as const,
              resolution: 'auto-detect',
              confidence: 1.0,
              tested: true,
              source: 'user-provided' as const
            }];
          }
        } catch (error) {
          const errorMessage = error instanceof Error ? error.message : String(error);
          this.logger.warn({ message: 'RTSP check failed', data: { cameraId: camera.id, error: errorMessage } });
          result.details.rtspError = errorMessage;
        }
      }
      
      // 4. Determine overall status
      result.overall = result.ping && (result.onvif || result.rtsp);
      
      // Update the timestamp to indicate when the check was completed
      result.timestamp = new Date();
      
      return result;
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      this.logger.error({ message: 'Error in heartbeat check', data: { cameraId: camera.id, error: errorMessage } });
      
      result.details.error = errorMessage;
      return result;
    }
  }

  // ===== MÉTODOS AUXILIARES =====

  /**
   * Retrieves detailed device information from an ONVIF device
   * @param device The ONVIF device instance
   * @returns Device information including manufacturer, model, firmware, and uptime
   */
  private async getDeviceInfo(device: onvif.Device): Promise<{
    manufacturer: string;
    model: string;
    firmware: string;
    uptime?: number;
  }> {
    const defaultResult = {
      manufacturer: 'Unknown',
      model: 'Unknown',
      firmware: 'Unknown'
    };

    try {
      // Get basic device information
      const deviceInfo = await new Promise<onvif.DeviceInfo>((resolve, reject) => {
        device.getDeviceInformation((err: Error | null, data: onvif.DeviceInfo) => {
          if (err) {
            this.logger.warn(`Failed to get device information: ${err.message}`);
            reject(err);
          } else {
            resolve(data);
          }
        });
      });
      
      const result = {
        manufacturer: deviceInfo.manufacturer || defaultResult.manufacturer,
        model: deviceInfo.model || defaultResult.model,
        firmware: deviceInfo.firmwareVersion || defaultResult.firmware
      };

      // Try to get system date and time to calculate uptime
      try {
        type SystemDateAndTime = {
          UTCDateTime?: {
            date?: { year?: number; month?: number; day?: number };
            time?: { hour?: number; minute?: number; second?: number };
          };
          LocalDateTime?: {
            date?: { year?: number; month?: number; day?: number };
            time?: { hour?: number; minute?: number; second?: number };
          };
          Timezone?: string;
        };

        const systemDate = await new Promise<SystemDateAndTime>((resolve, reject) => {
          device.getSystemDateAndTime((err: Error | null, data: any) => {
            if (err) {
              this.logger.warn(`Failed to get system date/time: ${err.message}`);
              reject(err);
            } else {
              resolve(data);
            }
          });
        });

        // Try to calculate uptime from UTC time first
        if (systemDate.UTCDateTime?.date && systemDate.UTCDateTime?.time) {
          const utcDate = systemDate.UTCDateTime.date;
          const utcTime = systemDate.UTCDateTime.time;
          
          // Validate required date/time fields
          if (utcDate.year !== undefined && utcDate.month !== undefined && utcDate.day !== undefined &&
              utcTime.hour !== undefined && utcTime.minute !== undefined && utcTime.second !== undefined) {
            
            const deviceTime = new Date(
              Date.UTC(
                utcDate.year,
                utcDate.month - 1, // JS months are 0-indexed
                utcDate.day,
                utcTime.hour,
                utcTime.minute,
                utcTime.second
              )
            );
            
            // If we have both local and UTC time, we can calculate timezone offset
            if (systemDate.LocalDateTime?.date && systemDate.LocalDateTime?.time) {
              const localDate = systemDate.LocalDateTime.date;
              const localTime = systemDate.LocalDateTime.time;
              
              if (localDate.year !== undefined && localDate.month !== undefined && localDate.day !== undefined &&
                  localTime.hour !== undefined && localTime.minute !== undefined && localTime.second !== undefined) {
                
                const localDeviceTime = new Date(
                  localDate.year,
                  localDate.month - 1,
                  localDate.day,
                  localTime.hour,
                  localTime.minute,
                  localTime.second
                );
                
                const timezoneOffsetMs = deviceTime.getTime() - localDeviceTime.getTime();
                const now = new Date();
                const uptimeMs = now.getTime() - (deviceTime.getTime() + timezoneOffsetMs);
                
                // Only include if it's a reasonable value (positive and less than 1 year)
                if (uptimeMs > 0 && uptimeMs < 365 * 24 * 60 * 60 * 1000) {
                  return {
                    ...result,
                    uptime: Math.floor(uptimeMs / 1000) // Convert to seconds
                  };
                }
              }
            }
            
            // Fallback to simple UTC-based calculation if local time is not available
            const now = new Date();
            const uptimeMs = now.getTime() - deviceTime.getTime();
            
            if (uptimeMs > 0 && uptimeMs < 365 * 24 * 60 * 60 * 1000) {
              return {
                ...result,
                uptime: Math.floor(uptimeMs / 1000) // Convert to seconds
              };
            }
          }
        }
      } catch (error) {
        this.logger.debug('Could not get system uptime', {
          error: error instanceof Error ? error.message : String(error)
        });
      }
      
      return result;
      
    } catch (error) {
      this.logger.error({ message: `Failed to get device info: ${error instanceof Error ? error.message : 'Unknown error'}` });
      return defaultResult;
    }
  }

  /**
   * Detects RTSP URLs for a given ONVIF device
   * @param device The ONVIF device to detect RTSP URLs for
   * @param config Optional manufacturer configuration
   * @returns Array of detected RTSP URLs with metadata
   */
  private async detectRTSPUrls(
    device: onvif.Device,
    config?: ManufacturerConfig | null
  ): Promise<RTSPUrlInfo[]> {
    try {
      if (!device || !device.hostname) {
        this.logger.warn({ message: 'Invalid device or missing hostname' });
        return [];
      }

      this.logger.debug('Detecting RTSP URLs for device', { hostname: device.hostname });
      const rtspUrls: RTSPUrlInfo[] = [];
      
      // 1. Try manufacturer paths if available
      if (config?.paths && Array.isArray(config.paths)) {
        for (const path of config.paths) {
          if (typeof path === 'string') {
            await this.testAndAddRTSPUrl(rtspUrls, device.hostname, path, 'manufacturer');
          }
        }
      }
      
      // 2. If no URLs found, try common paths
      if (rtspUrls.length === 0) {
        type CommonPath = { path: string; type: 'main' | 'sub' | 'mobile' };
        const commonPaths: CommonPath[] = [
          { path: '/Streaming/Channels/101', type: 'main' },
          { path: '/live.sdp', type: 'main' },
          { path: '/onvif1', type: 'main' },
          { path: '/media/video1', type: 'sub' },
          { path: '/cam/realmonitor?channel=1&subtype=0', type: 'main' }
        ];
        
        for (const { path, type } of commonPaths) {
          await this.testAndAddRTSPUrl(rtspUrls, device.hostname, path, type);
        }
      }
      
      return rtspUrls.filter((url): url is RTSPUrlInfo => url !== null);
    } catch (error) {
      this.logger.error('Error detecting RTSP URLs', { 
        hostname: device?.hostname || 'unknown',
        error: error instanceof Error ? error.message : String(error) 
      });
      return [];
    }
  }

  /**
   * Tests an RTSP URL and adds it to the list if it's reachable
   * @param rtspUrls Array of RTSP URL information
   * @param hostname Camera hostname or IP address
   * @param path RTSP path to test
   * @param source Source of the RTSP URL ('auto-detected', 'manual', 'discovered', 'user-defined', or stream type)
   * @param streamType Optional explicit stream type ('main', 'sub', 'mobile')
   */
  /**
   * Tests an RTSP URL and adds it to the list if it's reachable
   * @param rtspUrls Array of RTSP URL information
   * @param hostname Camera hostname or IP address
   * @param path RTSP path to test
   * @param source Source of the RTSP URL ('auto-detected', 'manual', 'discovered', 'user-defined', or stream type)
   * @param streamType Optional explicit stream type ('main', 'sub', 'mobile')
   */
  /**
   * Tests an RTSP URL and adds it to the list if it's reachable
   * @param rtspUrls Array of RTSP URL information
   * @param source Source of the RTSP URL ('auto-detected', 'manufacturer', 'common', or 'user-provided')
   * @param streamType Optional explicit stream type ('main', 'sub', 'mobile')
   */
  private async testAndAddRTSPUrl(
    rtspUrls: RTSPUrlInfo[],
    hostname: string,
    path: string,
    source: RTSPUrlInfo['source'],
    streamType?: RTSPUrlInfo['streamType']
  ): Promise<void> {
    if (!hostname) {
      this.logger?.warn?.('Cannot test RTSP URL: missing hostname');
      return;
    }

    // Map stream type strings to valid RTSPUrlInfo['source'] values
    const streamTypeToSource: Record<string, RTSPUrlInfo['source']> = {
      'main': 'manufacturer',
      'sub': 'manufacturer',
      'mobile': 'manufacturer',
      'snapshot': 'manufacturer',
      'event': 'manufacturer'
    };

    // Determine the final stream type (default to 'main' if not specified)
    const streamTypes = ['main', 'sub', 'mobile', 'snapshot', 'event'] as const;
    const finalStreamType: RTSPUrlInfo['streamType'] = streamType || 
      (streamTypes.includes(source as any) ? source as RTSPUrlInfo['streamType'] : 'main');
    
    // Normalize the source to ensure it's a valid RTSPUrlInfo['source']
    const validSources = ['manufacturer', 'common', 'auto-detected', 'user-provided'] as const;
    const sourceStr = String(source);
    const normalizedSource = validSources.includes(sourceStr as any) 
      ? sourceStr as RTSPUrlInfo['source']
      : streamTypeToSource[sourceStr] || 'auto-detected';
    
    // Clean up the path (ensure it starts with /)
    const cleanPath = path.startsWith('/') ? path : `/${path}`;
    
    // Construct the full RTSP URL
    const url = `rtsp://${hostname}${cleanPath}`;
    
    // Check if we've already tested this URL (case-insensitive check)
    const existingUrlIndex = rtspUrls.findIndex(u => u.url.toLowerCase() === url.toLowerCase());
    if (existingUrlIndex >= 0) {
      this.logger.debug(`Skipping already tested URL: ${url}`);
      return;
    }

    try {
      // Test the RTSP connection
      const isReachable = await this.testRTSPConnection(url);
      
      // Create RTSP URL info with all required properties
      const rtspUrlInfo: RTSPUrlInfo = {
        url,
        streamType: finalStreamType,
        resolution: 'auto-detect',
        confidence: isReachable ? 0.9 : 0.1, // Higher confidence if reachable
        tested: true,
        source: normalizedSource, // Now properly typed as RTSPUrlInfo['source']
        // Optional properties with default values
        authType: 'none',
        bitrate: 0,
        framerate: 0,
        codec: 'H.264' as const
      };
      
      if (isReachable) {
        rtspUrls.push(rtspUrlInfo);
        this.logger.debug(`Successfully tested RTSP URL: ${url}`, {
          streamType: finalStreamType,
          source: normalizedSource,
          confidence: rtspUrlInfo.confidence
        });
      } else {
        // Still add the URL but with lower confidence
        rtspUrls.push({
          ...rtspUrlInfo,
          confidence: 0.1,
          tested: false
        });
        this.logger.debug(`RTSP URL not reachable: ${url}`);
      }
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      this.logger.error(`Error testing RTSP URL ${url}: ${errorMessage}`);
      
      // Add the failed URL with low confidence
      rtspUrls.push({
        url,
        streamType: finalStreamType,
        resolution: 'unknown',
        confidence: 0.1,
        tested: false,
        source: normalizedSource,
        error: errorMessage,
        authType: 'none',
        bitrate: 0,
        framerate: 0
      });
    }
  }

  private extractCodecs(capabilities: any): string[] {
    const codecs: string[] = [];
    
    if (!capabilities) {
      return codecs;
    }

    // Extract video codecs
    if (capabilities.media?.video?.encoder?.codec) {
      const videoCodec = capabilities.media.video.encoder.codec.toLowerCase();
      if (videoCodec.includes('h264') || videoCodec.includes('h.264')) {
        codecs.push('H.264');
      } else if (videoCodec.includes('h265') || videoCodec.includes('h.265') || videoCodec.includes('hevc')) {
        codecs.push('H.265');
      } else if (videoCodec.includes('mjpeg') || videoCodec.includes('m-jpeg')) {
        codecs.push('MJPEG');
      } else if (videoCodec.includes('mpeg4')) {
        codecs.push('MPEG-4');
      }
    }

    // Extract audio codecs if available
    if (capabilities.media?.audio?.encoder?.codec) {
      const audioCodec = capabilities.media.audio.encoder.codec.toLowerCase();
      if (audioCodec.includes('g711') || audioCodec.includes('g.711')) {
        codecs.push('G.711');
      } else if (audioCodec.includes('g722') || audioCodec.includes('g.722')) {
        codecs.push('G.722');
      } else if (audioCodec.includes('g726') || audioCodec.includes('g.726')) {
        codecs.push('G.726');
      } else if (audioCodec.includes('aac')) {
        codecs.push('AAC');
      } else if (audioCodec.includes('pcm')) {
        codecs.push('PCM');
      }
    }

    return codecs.length > 0 ? codecs : ['H.264']; // Default value
  }
}
