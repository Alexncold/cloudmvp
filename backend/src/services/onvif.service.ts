import { EventEmitter } from 'events';
import * as onvif from 'node-onvif';
import { promisify } from 'util';
import { spawn } from 'child_process';
import { Camera } from '@prisma/client';
import { CameraConfigDatabase } from '../utils/camera-config-database';
import { EncryptionService } from './encryption.service';
import { logger } from '../utils/logger';
import { 
  DiscoveredCamera, 
  RTSPUrlInfo, 
  ValidationResult, 
  CameraCapabilities, 
  SuggestedCredential,
  CameraDiscoveryOptions,
  CameraConnectionOptions
} from '../../../shared/types/onvif';

type OnvifDevice = onvif.Device;

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
  private onvifManager: typeof onvif;
  private configDatabase: CameraConfigDatabase;
  private encryptionService: EncryptionService;
  private discoveryCache = new Map<string, DiscoveredCamera>();
  private pingCache = new Map<string, { timestamp: number; result: boolean }>();
  private readonly PING_CACHE_TTL = 30000; // 30 segundos
  private logger = logger; // Add logger as a class property

  /**
   * Retrieves device information from an ONVIF device
   * @param device The ONVIF device instance
   * @returns Device information including manufacturer, model, firmware, and uptime
   */
  private async getDeviceInfo(device: onvif.Device): Promise<{
    manufacturer: string;
    model: string;
    firmware: string;
    uptime?: number;
  }> {
    try {
      // Get basic device information
      const deviceInfo = await promisify(device.getDeviceInformation).call(device);
      
      // Get system date and time for uptime calculation if supported
      let uptime: number | undefined;
      try {
        const systemDate = await promisify(device.getSystemDateAndTime).call(device);
        if (systemDate && systemDate.UTCDateTime) {
          const now = new Date();
          const deviceTime = new Date(
            systemDate.UTCDateTime.date.year,
            (systemDate.UTCDateTime.date.month || 1) - 1,
            systemDate.UTCDateTime.date.day || 1,
            systemDate.UTCDateTime.time.hour || 0,
            systemDate.UTCDateTime.time.minute || 0,
            systemDate.UTCDateTime.time.second || 0
          );
          
          // Calculate uptime in seconds (this is an approximation)
          uptime = Math.floor((now.getTime() - deviceTime.getTime()) / 1000);
        }
      } catch (error) {
        this.logger.debug('Could not get system date/time from device', { 
          error: error instanceof Error ? error.message : String(error) 
        });
      }
      
      return {
        manufacturer: deviceInfo.manufacturer || 'Unknown',
        model: deviceInfo.model || 'Unknown',
        firmware: deviceInfo.firmwareVersion || 'Unknown',
        uptime
      };
    } catch (error) {
      this.logger.warn('Failed to get device information', { 
        error: error instanceof Error ? error.message : String(error) 
      });
      return {
        manufacturer: 'Unknown',
        model: 'Unknown',
        firmware: 'Unknown'
      };
    }
  }

  constructor() {
    super();
    this.onvifManager = onvif;
    this.configDatabase = new CameraConfigDatabase();
    this.encryptionService = new EncryptionService();
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
  private async testRTSPConnection(rtspUrl: string): Promise<boolean> {
    return new Promise<boolean>((resolve) => {
      const ffprobe = spawn('ffprobe', [
        '-v', 'error',
        '-select_streams', 'v:0',
        '-show_entries', 'stream=codec_name,width,height',
        '-of', 'json',
        rtspUrl
      ]);
      
      let output = '';
      let errorOutput = '';
      
      ffprobe.stdout.on('data', (data) => {
        output += data.toString();
      });
      
      ffprobe.stderr.on('data', (data) => {
        errorOutput += data.toString();
      });
      
      ffprobe.on('close', (code) => {
        if (code === 0) {
          try {
            const result = JSON.parse(output);
            resolve(!!result.streams?.[0]);
          } catch {
            resolve(false);
          }
        } else {
          logger.debug('Error en ffprobe', { error: errorOutput });
          resolve(false);
        }
      });
      
      // Timeout after 10 seconds
      setTimeout(() => {
        if (!ffprobe.killed) {
          ffprobe.kill();
          resolve(false);
        }
      }, 10000);
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
      this.logger.warn(`Camera at ${ip} is not reachable`);
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
  private async detectCapabilities(device: onvif.Device, manufacturer?: string): Promise<{
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
  }> {
    // Define the base capabilities with default values
    const baseCapabilities = {
      hasPTZ: false,
      hasAudio: false,
      hasMotionDetection: false,
      hasNightVision: false,
      hasInfrared: false,
      hasZoom: false,
      hasFocus: false,
      hasIris: false,
      hasPresets: false,
      hasEvents: false,
      hasAnalytics: false,
      resolutions: ['1920x1080', '1280x720'],
      codecs: ['H.264'],
      maxFrameRate: 30,
      onvifVersion: '1.0',
      profiles: [] as any[],
      manufacturerFeatures: {} as Record<string, boolean>
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

        const ptzStatus = await new Promise<PTZStatus>((resolve) => {
          device.getStatus({ ProfileToken: 'Profile_1' }, (err: Error | null, data?: unknown) => {
            if (err) {
              this.logger.debug(`PTZ status check failed: ${err.message}`, { error: err });
              resolve({});
            } else {
              resolve((data as PTZStatus) || {});
            }
          });
        });
        
        if (ptzStatus?.position) {
          baseCapabilities.hasPTZ = true;
          const position = ptzStatus.position;
          
          // Check for specific PTZ capabilities
          baseCapabilities.hasZoom = 'zoom' in position;
          baseCapabilities.hasFocus = 'focus' in position;
          baseCapabilities.hasIris = 'iris' in position;
          
          // Check for presets
          try {
            const presets = await new Promise<any[]>((resolve, reject) => {
              device.getPresets({ ProfileToken: 'Profile_1' }, (err, data) => {
                if (err) reject(err);
                else resolve(data);
              });
            });
            baseCapabilities.hasPresets = Array.isArray(presets) && presets.length > 0;
          } catch (presetError) {
            this.logger.debug('Presets not supported', {
              error: presetError instanceof Error ? presetError.message : String(presetError)
            });
          }
        }
      } catch (error) {
        this.logger.debug('PTZ capabilities not supported', { 
          error: error instanceof Error ? error.message : String(error) 
        });
      }

      // Get profiles and check for audio
      try {
        const profiles = await new Promise<any[]>((resolve, reject) => {
          device.getProfiles((err, data) => {
            if (err) reject(err);
            else resolve(data);
          });
        });
        
        baseCapabilities.profiles = Array.isArray(profiles) ? profiles : [];
        
        if (profiles?.[0]) {
          const profile = profiles[0];
          
          // Check for audio support
          try {
            const audioSources = await new Promise<any[]>((resolve, reject) => {
              device.getAudioSources((err, data) => {
                if (err) reject(err);
                else resolve(data);
              });
            });
            baseCapabilities.hasAudio = Array.isArray(audioSources) && audioSources.length > 0;
          } catch (audioError) {
            this.logger.debug('Audio sources not available', {
              error: audioError instanceof Error ? audioError.message : String(audioError)
            });
          }
          
          // Extract video configuration
          if (profile.VideoEncoderConfiguration?.$?.token) {
            try {
              const videoConfig = await new Promise<any>((resolve, reject) => {
                device.getVideoEncoderConfiguration({
                  ConfigurationToken: profile.VideoEncoderConfiguration.$.token
                }, (err, data) => {
                  if (err) reject(err);
                  else resolve(data);
                });
              });
              
              if (videoConfig?.Resolution) {
                const width = videoConfig.Resolution.Width || 1920;
                const height = videoConfig.Resolution.Height || 1080;
                baseCapabilities.resolutions = [`${width}x${height}`];
              }
              
              if (videoConfig?.Encoding) {
                baseCapabilities.codecs = [videoConfig.Encoding];
              }
              
              if (videoConfig?.RateControl?.FrameRateLimit) {
                baseCapabilities.maxFrameRate = Number(videoConfig.RateControl.FrameRateLimit) || 30;
              }
            } catch (videoError) {
              this.logger.debug('Failed to get video configuration', {
                error: videoError instanceof Error ? videoError.message : String(videoError)
              });
            }
          }
        }
      } catch (error) {
        this.logger.debug('Failed to get profiles', {
          error: error instanceof Error ? error.message : String(error)
        });
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
              this.logger.debug('Failed to get analytics configurations', { 
                error: err.message 
              });
              resolve([]);
            } else {
              resolve(Array.isArray(data) ? data : []);
            }
          });
        });

        if (analytics.length > 0) {
          baseCapabilities.hasMotionDetection = analytics.some(
            (config) => config?.AnalyticsEngineConfiguration?.MotionRegionDetection !== undefined
          );
          baseCapabilities.hasAnalytics = true;
        }
      } catch (error) {
        this.logger.debug('Analytics not supported', { 
          error: error instanceof Error ? error.message : String(error) 
        });
      }

      // Check for events
      try {
        const events = await promisify(device.getEventProperties).call(device);
        baseCapabilities.hasEvents = !!events;
      } catch (error) {
        // Events not supported
      }

      // Check for presets
      try {
        const presets = await promisify(device.getPresets).call(device, { ProfileToken: 'Profile_1' });
        baseCapabilities.hasPresets = !!(presets && presets.length > 0);
      } catch (error) {
        // Presets not supported
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

        const videoSources = await promisify<VideoSource[], []>(device.getVideoSources).call(device);
        if (videoSources?.[0]?.$) {
          const videoSource = videoSources[0].$;
          
          // Usar type assertion para acceder a propiedades específicas del fabricante
          baseCapabilities.hasNightVision = 'DayNight' in videoSource;
          baseCapabilities.hasInfrared = 'InfraredCutFilter' in videoSource;
          
          // Add manufacturer-specific features
          if (manufacturer) {
            const normalizedManufacturer = manufacturer.toLowerCase();
            baseCapabilities.manufacturerFeatures = {
              isHikvision: normalizedManufacturer.includes('hikvision'),
              isDahua: normalizedManufacturer.includes('dahua'),
              isAxis: normalizedManufacturer.includes('axis'),
              isSony: normalizedManufacturer.includes('sony'),
              isBosch: normalizedManufacturer.includes('bosch')
            };
            
            // Set night vision based on manufacturer if not detected
            if (!baseCapabilities.hasNightVision) {
              baseCapabilities.hasNightVision = 
                normalizedManufacturer.includes('hikvision') || 
                normalizedManufacturer.includes('dahua');
            }
          }
        }
      } catch (error) {
        this.logger.debug('Could not determine night vision/infrared capabilities', { 
          error: error instanceof Error ? error.message : String(error) 
        });
      }
      
      return baseCapabilities;
    } catch (error) {
      logger.error('Error detecting camera capabilities:', error);
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
    logger.info('Iniciando descubrimiento de cámaras', { timeoutMs });
    this.discoveryCache.clear();

    try {
      // Usar promisify para convertir el callback a promesa
      const discoverDevices = promisify(this.onvifManager.Discover.on('device', () => {}));
      
      // Configurar timeout
      const discoveryPromise = new Promise<onvif.Device[]>((resolve) => {
        const devices: onvif.Device[] = [];
        const discover = this.onvifManager.Discover;
        
        discover.on('device', (device: onvif.Device) => {
          devices.push(device);
        });
        
        // Forzar finalización después del timeout
        setTimeout(() => {
          discover.socket.close();
          resolve(devices);
        }, timeoutMs);
      });

      // Esperar a que termine el descubrimiento o el timeout
      const devices = await discoveryPromise;
      
      // Procesar dispositivos en paralelo
      const discoveryPromises = devices.map(device => this.processDiscoveredDevice(device));
      const results = await Promise.allSettled(discoveryPromises);
      
      // Filtrar resultados exitosos
      const discoveredCameras = results
        .filter((result): result is PromiseFulfilledResult<DiscoveredCamera> => 
          result.status === 'fulfilled' && result.value !== null
        )
        .map(result => result.value);
      
      logger.log(`Descubrimiento completado. Se encontraron ${discoveredCameras.length} cámaras válidas`);
      
      return discoveredCameras;
    } catch (error) {
      logger.error('Error durante el descubrimiento de cámaras:', error);
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
      this.logger.warn('Error al procesar dispositivo', { 
        ip: device.hostname, 
        error: error instanceof Error ? error.message : String(error) 
      });
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
      const device = new this.onvifManager.OnvifDevice({
        xaddr: `http://${ip}:${port}/onvif/device_service`,
        user: username,
        pass: password
      });
      
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
      result.confidence = this.calculateConfidence(
        result.rtspSupport ? [{ url: result.detectedRtspUrl, streamType: 'main', resolution: 'auto-detect', confidence: 1 }] : [],
        result.valid ? [{ username, password, confidence: 1, testedUrl: result.detectedRtspUrl || '', authType: 'digest' }] : [],
        result.manufacturer
      );
      
      return result;
    } catch (error) {
      this.logger.warn('Validación de cámara fallida', { 
        ip, 
        error: error instanceof Error ? error.message : String(error) 
      });
      
      if (!result.onvifSupport && !result.rtspSupport) {
        result.error = 'No se pudo conectar a la cámara con las credenciales proporcionadas';
      } else if (!result.rtspSupport) {
        result.error = 'No se pudo acceder al stream RTSP con la ruta proporcionada';
      }
      
      return result;
    }
  }

/**
 * Result of a camera heartbeat check
 */
interface HeartbeatResult {
  /** Camera ID */
  cameraId: string;
  /** Overall status (true if both ping and ONVIF are working) */
  overall: boolean;
  /** Whether the camera responded to ping */
  ping: boolean;
  /** Whether ONVIF communication is working */
  onvif: boolean;
  /** Whether RTSP stream is accessible */
  rtsp: boolean;
  /** When the heartbeat was performed */
  timestamp: Date;
  /** When the camera was last seen */
  lastSeen: Date;
  /** Camera uptime in seconds, if available */
  uptime?: number;
  /** Additional details about the heartbeat result */
  details: {
    /** Error details for ping check */
    pingError?: string;
    /** Error details for ONVIF check */
    onvifError?: string;
    /** Error details for RTSP check */
    rtspError?: string;
    /** Device information if ONVIF check succeeded */
    deviceInfo?: {
      manufacturer: string;
      model: string;
      firmware: string;
      uptime?: number;
    };
    /** List of available RTSP URLs if RTSP check succeeded */
    rtspUrls?: Array<{
      url: string;
      streamType: 'main' | 'sub' | 'mobile';
      resolution: string;
      tested: boolean;
      source: string;
    }>;
    /** Any additional error information */
    error?: string;
    [key: string]: any;
  };
}

  /**
   * Performs a heartbeat check on a camera to verify its status
   * @param camera Camera configuration
   * @returns Heartbeat result with detailed status information
   */
  public async performHeartbeat(camera: Camera & { password_encrypted?: string; manufacturer?: string }): Promise<HeartbeatResult> {
    const result: HeartbeatResult = {
      cameraId: camera.id,
      overall: false,
      ping: false,
      onvif: false,
      rtsp: false,
      timestamp: new Date(),
      details: {},
      lastSeen: new Date()
    };

    try {
      // 1. Check basic connectivity with ping
      result.ping = await this.pingCamera(camera.ipAddress);
      
      if (!result.ping) {
        this.logger.warn(`Camera not reachable by ping`, { cameraId: camera.id });
        result.details.pingError = 'Device not reachable';
        return result;
      }
      
      // 2. Check ONVIF service if credentials are available
      if (camera.username) {
        try {
          const password = camera.password_encrypted 
            ? await this.encryptionService.decrypt(camera.password_encrypted) 
            : '';
            
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
          
          // Include device info in details
          if (deviceInfo) {
            result.details.deviceInfo = deviceInfo;
            if (deviceInfo.uptime) {
              result.uptime = deviceInfo.uptime;
            }
          }
        result.onvif = true;
      } catch (error) {
        this.logger.warn(`Fallo en conexión ONVIF`, { 
          cameraId: camera.id, 
          error: error instanceof Error ? error.message : String(error) 
        });
      }
      
      // 3. Verificar RTSP
      if (camera.rtspUrl) {
        const password = camera.password_encrypted ? await this.encryptionService.decrypt(camera.password_encrypted) : '';
        const rtspUrl = camera.rtspUrl
          .replace('rtsp://', `rtsp://${camera.username}:${password}@`);
          
        result.rtsp = await this.testRTSPConnection(rtspUrl);
        
        if (!result.rtsp) {
          this.logger.warn(`Fallo en conexión RTSP`, { cameraId: camera.id });
        }
      }
      
      // 4. Determinar estado general
      result.overall = result.ping && (result.onvif || result.rtsp);
      
      return result;
    } catch (error) {
      this.logger.error('Error en el heartbeat', { 
        cameraId: camera.id, 
        error: error instanceof Error ? error.message : String(error) 
      });
      
      result.details.error = error instanceof Error ? error.message : 'Unknown error';
      return result;
    }
  }

  // ===== MÉTODOS AUXILIARES =====

  private async getDeviceInfo(device: onvif.Device): Promise<{
    manufacturer: string;
    model: string;
    firmware: string;
    uptime?: number;
  }> {
    try {
      // Get basic device information
      const deviceInfo = await promisify(device.getDeviceInformation).call(device);
      const result = {
        manufacturer: deviceInfo.manufacturer || 'Unknown',
        model: deviceInfo.model || 'Unknown',
        firmware: deviceInfo.firmwareVersion || 'Unknown'
      };

      // Try to get system date and time to calculate uptime
      try {
        const systemDate = await promisify(device.getSystemDateAndTime).call(device);
        if (systemDate.UTCDateTime) {
          const deviceTime = new Date(
            Date.UTC(
              systemDate.UTCDateTime.date.year,
              systemDate.UTCDateTime.date.month - 1, // JS months are 0-indexed
              systemDate.UTCDateTime.date.day,
              systemDate.UTCDateTime.time.hour,
              systemDate.UTCDateTime.time.minute,
              systemDate.UTCDateTime.time.second
            )
          );
          
          // If we have both local and UTC time, we can calculate uptime
          if (systemDate.LocalDateTime) {
            const localDeviceTime = new Date(
              Date.UTC(
                systemDate.LocalDateTime.date.year,
                systemDate.LocalDateTime.date.month - 1,
                systemDate.LocalDateTime.date.day,
                systemDate.LocalDateTime.time.hour,
                systemDate.LocalDateTime.time.minute,
                systemDate.LocalDateTime.time.second
              )
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
      } catch (error) {
        logger.debug('Could not get system uptime', {
          error: error instanceof Error ? error.message : String(error)
        });
      }
      
      return {
        manufacturer: deviceInfo.manufacturer || 'Unknown',
        model: deviceInfo.model || 'Unknown',
        firmware: deviceInfo.firmwareVersion || 'Unknown'
      };
    } catch (error) {
      logger.error('Error getting device info:', error);
      return {
        manufacturer: 'Unknown',
        model: 'Unknown',
        firmware: 'Unknown'
      };
    }
  }

  /**
   * Detecta las URLs RTSP disponibles para un dispositivo ONVIF
   * @param device Dispositivo ONVIF
   * @param config Configuración del fabricante (opcional)
   * @returns Lista de URLs RTSP detectadas con metadatos
   */
  private async detectRTSPUrls(
    device: onvif.Device,
    config?: ReturnType<CameraConfigDatabase['getManufacturerConfig']>
  ): Promise<RTSPUrlInfo[]> {
    this.logger.debug('Detectando URLs RTSP para el dispositivo', { hostname: device.hostname });
    const rtspUrls: RTSPUrlInfo[] = [];
    
    try {
      // 1. Intentar con las rutas del fabricante si están disponibles
      if (config?.rtsp?.paths) {
        for (const path of config.rtsp.paths) {
          await this.testAndAddRTSPUrl(rtspUrls, device.hostname, path, 'manufacturer');
        }
      }
      
      // 2. Si no se encontraron URLs, intentar con rutas comunes
      if (rtspUrls.length === 0) {
        const commonPaths = [
          { path: '/Streaming/Channels/101', type: 'main' as const },
          { path: '/live.sdp', type: 'main' as const },
          { path: '/onvif1', type: 'main' as const },
          { path: '/media/video1', type: 'sub' as const },
          { path: '/cam/realmonitor?channel=1&subtype=0', type: 'main' as const }
        ];
        
        for (const { path, type } of commonPaths) {
          await this.testAndAddRTSPUrl(rtspUrls, device.hostname, path, type);
        }
      }
      
      return rtspUrls;
    } catch (error) {
      this.logger.error('Error al detectar URLs RTSP', { 
        hostname: device.hostname,
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
   * @param source Source of the RTSP URL (e.g., 'manufacturer', 'common', 'auto-detected')
   * @param streamType Type of stream ('main', 'sub', 'mobile')
   */
  private async testAndAddRTSPUrl(
    rtspUrls: RTSPUrlInfo[],
    hostname: string,
    path: string,
    source: RTSPUrlInfo['source'] | 'main' | 'sub' | 'mobile',
    streamType?: 'main' | 'sub' | 'mobile'
  ): Promise<void> {
    // Normalize source to match RTSPUrlInfo['source'] type
    const normalizedSource: RTSPUrlInfo['source'] = 
      (source === 'main' || source === 'sub' || source === 'mobile') ? 'auto-detected' : source;

    // Determine stream type if not provided
    const finalStreamType = streamType || 
      (source === 'main' || source === 'sub' || source === 'mobile' ? source : 'main');
    
    try {
      // Clean up the path (remove leading slash if present and ensure it starts with /)
      const cleanPath = path.startsWith('/') ? path : `/${path}`;
      
      // Construct the full RTSP URL
      const url = `rtsp://${hostname}${cleanPath}`;
      
      // Check if we've already tested this URL
      const existingIndex = rtspUrls.findIndex(u => u.url === url);
      if (existingIndex >= 0) {
        this.logger.debug(`Skipping already tested URL: ${url}`);
        return;
      }
      
      // Test the RTSP connection
      const isReachable = await this.testRTSPConnection(url);
      
      if (isReachable) {
        // Create a new RTSP URL info object
        const newUrlInfo: RTSPUrlInfo = {
          url,
          streamType: finalStreamType,
          resolution: 'auto-detect', // Will be updated later
          confidence: 0.8, // Base confidence
          tested: true,
          source: normalizedSource,
          authType: 'none', // Will be updated during authentication
          bitrate: 0, // Will be updated during stream analysis
          framerate: 0, // Will be updated during stream analysis
          codec: 'h264' // Default, will be updated during stream analysis
        };
        
        // Check if we already have this URL with a different case
        const existingUrlIndex = rtspUrls.findIndex(u => u.url.toLowerCase() === url.toLowerCase());
        
        if (existingUrlIndex >= 0) {
          // Update existing entry with new confidence and source if higher confidence
          if (newUrlInfo.confidence > rtspUrls[existingUrlIndex].confidence) {
            rtspUrls[existingUrlIndex] = {
              ...rtspUrls[existingUrlIndex],
              ...newUrlInfo
            };
            this.logger.debug(`Updated RTSP URL with higher confidence: ${url}`, {
              streamType: finalStreamType,
              source: normalizedSource,
              confidence: newUrlInfo.confidence
            });
          }
        } else {
          // Add new URL
          rtspUrls.push(newUrlInfo);
          this.logger.debug(`Added new RTSP URL: ${url}`, {
            streamType: finalStreamType,
            source: normalizedSource,
            confidence: newUrlInfo.confidence
          });
        }
      } else {
        this.logger.debug(`RTSP URL not reachable: ${url}`);
      }
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      this.logger.error(`Error testing RTSP URL ${hostname}${path}: ${errorMessage}`);
    }
  }

  /**
   * Performs a heartbeat check on a camera to verify its status
   * @param camera Camera object with connection details
   * @returns Promise with the heartbeat result
   */
      rtsp: false,
      timestamp: new Date(),
      details: {}
    };

    try {
      // Check if camera is reachable via ping
      result.ping = await this.pingCamera(camera.ipAddress);
      if (!result.ping) {
        result.details.pingError = 'Device not reachable';
        return result;
      }

      // Check ONVIF connectivity
      try {
        const device = await this.createOnvifClient({
          ipAddress: camera.ipAddress,
          port: camera.port || 80,
          username: camera.username || '',
          password: camera.password ? await this.encryptionService.decrypt(camera.password) : ''
        });
        
        result.onvif = true;
        
        // Check RTSP streams if ONVIF is working
        const rtspUrls = await this.detectRTSPUrls(device);
        if (rtspUrls && rtspUrls.length > 0) {
          result.rtsp = true;
          result.details.rtspUrls = rtspUrls;
        } else {
          result.details.rtspError = 'No RTSP streams found';
        }
      } catch (error) {
        result.details.onvifError = error instanceof Error ? error.message : 'Unknown error';
      }

      // Overall status is true if both ping and ONVIF are working
      result.overall = result.ping && result.onvif;
      
      return result;
    } catch (error) {
      this.logger.error('Error performing heartbeat check:', error);
      result.details.error = error instanceof Error ? error.message : 'Unknown error';
      return result;
    }
  }

  async performHeartbeat(camera: Camera & { password_encrypted?: string; manufacturer?: string }): Promise<{
    isOnline: boolean;
    ping: boolean;
    onvif: boolean;
    rtsp: boolean;
    lastSeen?: Date;
    uptime?: number;
    error?: string;
  }> {
    const { ipAddress, port = 80, username, password, manufacturer } = camera;
    const result = {
      isOnline: false,
      ping: false,
      onvif: false,
      rtsp: false,
      lastSeen: new Date()
    };

    try {
      // 1. Check basic connectivity with ping
      result.ping = await this.pingCamera(ipAddress);
      
      if (!result.ping) {
        return { ...result, isOnline: false, error: 'No response to ping' };
      }

      // 2. Check ONVIF service if credentials are available
      if (username && password) {
        try {
          const device = await this.createOnvifClient({
            hostname: ipAddress,
            port,
            username,
            password,
            manufacturer
          });
          
          if (device) {
            // Try to get device info to verify ONVIF is working
            const deviceInfo = await this.getDeviceInfo(device);
            result.onvif = !!deviceInfo;
            
            // If we have uptime info, include it
            if (deviceInfo?.uptime) {
              result.uptime = deviceInfo.uptime;
            }
          }
        } catch (error) {
          this.logger.warn(`ONVIF check failed for ${ipAddress}:`, error instanceof Error ? error.message : String(error));
          result.onvif = false;
        }
      }

      // 3. Check RTSP stream
      if (result.onvif && username && password) {
        try {
          // Try to detect RTSP URLs if not provided
          const device = await this.createOnvifClient({
            hostname: ipAddress,
            port,
            username,
            password,
            manufacturer
          });
          
          if (device) {
            const config = this.configDatabase.getManufacturerConfig(manufacturer || '');
            const rtspUrls = await this.detectRTSPUrls(device, config);
            
            if (rtspUrls.length > 0) {
              // Test the first available RTSP URL
              const testUrl = rtspUrls[0].url;
              result.rtsp = await this.testRTSPConnection(testUrl);
            }
          }
        } catch (error) {
          this.logger.warn(`RTSP check failed for ${ipAddress}:`, error instanceof Error ? error.message : String(error));
          result.rtsp = false;
        }
      }

      // Determine if camera is considered online
      // We consider it online if it responds to ping AND (has ONVIF or RTSP working)
      result.isOnline = result.ping && (result.onvif || result.rtsp);
      
      return result;
    } catch (error) {
      this.logger.error(`Heartbeat failed for ${ipAddress}:`, error instanceof Error ? error.message : String(error));
      return {
        ...result,
        isOnline: false,
        error: error instanceof Error ? error.message : 'Unknown error during heartbeat check'
      };
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

  private calculateConfidence(
    rtspUrls: RTSPUrlInfo[],
    credentials: SuggestedCredential[],
    manufacturer: string
  ): number {
    // Peso para cada factor de confianza
    const WEIGHTS = {
      MANUFACTURER_KNOWN: 0.3,
      RTSP_URL_VALID: 0.4,
      CREDENTIALS_VALID: 0.3
    };

    let score = 0;
    
    // Puntuar fabricante conocido
    if (manufacturer !== 'generic') {
      score += WEIGHTS.MANUFACTURER_KNOWN;
    }
    
    // Puntuar URLs RTSP válidas
    const rtspScore = rtspUrls.reduce((sum, url) => sum + url.confidence, 0) / Math.max(rtspUrls.length, 1);
    score += rtspScore * WEIGHTS.RTSP_URL_VALID;
    
    // Puntuar credenciales válidas
    if (credentials.length > 0) {
      const credScore = credentials.reduce((sum, cred) => sum + cred.confidence, 0) / credentials.length;
      score += credScore * WEIGHTS.CREDENTIALS_VALID;
    }
    
    // Asegurar que el resultado esté entre 0 y 1
    return Math.min(Math.max(score, 0), 1);
  }
}
