import { EventEmitter } from 'events';
import * as onvif from 'node-onvif';
import { promisify } from 'util';
import { spawn } from 'child_process';
import { Camera } from '@prisma/client';
import { CameraConfigDatabase } from '../utils/camera-config-database';
import { EncryptionService } from './encryption.service';
import { Logger } from '../utils/logger';
import { DiscoveredCamera, RTSPUrlInfo, ValidationResult, HeartbeatResult } from '../../../shared/types/onvif';

export class ONVIFService extends EventEmitter {
  private onvifManager: typeof onvif;
  private configDatabase: CameraConfigDatabase;
  private encryptionService: EncryptionService;
  private logger: Logger;
  private discoveryCache = new Map<string, DiscoveredCamera>();
  private pingCache = new Map<string, { timestamp: number; result: boolean }>();
  private readonly PING_CACHE_TTL = 30000; // 30 segundos

  constructor() {
    super();
    this.onvifManager = onvif;
    this.configDatabase = new CameraConfigDatabase();
    this.encryptionService = new EncryptionService();
    this.logger = new Logger('ONVIFService');
  }

  /**
   * Descubre cámaras en la red local usando WS-Discovery
   */
  async discoverCameras(timeoutMs: number = 10000): Promise<DiscoveredCamera[]> {
    this.logger.info('Iniciando descubrimiento de cámaras', { timeoutMs });
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
      
      this.logger.info('Descubrimiento completado', { 
        total: devices.length, 
        valid: discoveredCameras.length 
      });
      
      return discoveredCameras;
    } catch (error) {
      this.logger.error('Error durante el descubrimiento de cámaras', { 
        error: error instanceof Error ? error.message : String(error) 
      });
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
      const suggestedCredentials = await this.detectCommonCredentials(device, config);
      
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
   * Realiza un heartbeat para verificar el estado de una cámara
   */
  async performHeartbeat(camera: Camera): Promise<HeartbeatResult> {
    const result: HeartbeatResult = {
      cameraId: camera.id,
      overall: false,
      ping: false,
      onvif: false,
      rtsp: false,
      timestamp: new Date()
    };

    try {
      // 1. Verificar ping
      result.ping = await this.pingCamera(camera.ip_address);
      
      if (!result.ping) {
        this.logger.warn(`Cámara inalcanzable por ping`, { cameraId: camera.id });
        return result;
      }
      
      // 2. Verificar ONVIF
      try {
        const password = this.encryptionService.decrypt(camera.password_encrypted);
        const device = new this.onvifManager.OnvifDevice({
          xaddr: `http://${camera.ip_address}:${camera.port}/onvif/device_service`,
          user: camera.username,
          pass: password
        });
        
        await this.getDeviceInfo(device);
        result.onvif = true;
      } catch (error) {
        this.logger.warn(`Fallo en conexión ONVIF`, { 
          cameraId: camera.id, 
          error: error instanceof Error ? error.message : String(error) 
        });
      }
      
      // 3. Verificar RTSP
      if (camera.rtsp_url) {
        const password = this.encryptionService.decrypt(camera.password_encrypted);
        const rtspUrl = camera.rtsp_url
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
      
      result.error = error instanceof Error ? error.message : String(error);
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
        this.logger.debug('Could not get system uptime', {
          error: error instanceof Error ? error.message : String(error)
        });
      }
      
      return result;
    } catch (error) {
      this.logger.warn('No se pudo obtener información del dispositivo', { 
        error: error instanceof Error ? error.message : String(error) 
      });
      return { 
        manufacturer: 'Unknown', 
        model: 'Unknown', 
        firmware: 'Unknown' 
      };
    }
  }

  private async detectRTSPUrls(
    device: onvif.Device,
    config: ReturnType<CameraConfigDatabase['getManufacturerConfig']>
  ): Promise<RTSPUrlInfo[]> {
    const rtspUrls: RTSPUrlInfo[] = [];
    
    // Probar rutas RTSP comunes para el fabricante
    for (const path of config.rtspPaths) {
      const url = `rtsp://${device.hostname}:554${path}`;
      const streamType = this.determineStreamType(path);
      
      rtspUrls.push({
        url,
        streamType,
        resolution: this.extractResolutionFromPath(path),
        confidence: 0.7 // Confianza media para rutas específicas del fabricante
      });
    }
    
    return rtspUrls;
  }

  private async detectCommonCredentials(
    device: onvif.Device,
    config: ReturnType<CameraConfigDatabase['getManufacturerConfig']>
  ) {
    const credentials = [];
    
    for (const cred of config.commonCredentials) {
      try {
        const testDevice = new this.onvifManager.OnvifDevice({
          xaddr: device.xaddr,
          user: cred.username,
          pass: cred.password
        });
        
        // Si no hay error, las credenciales son válidas
        await promisify(testDevice.init).call(testDevice);
        
        credentials.push({
          username: cred.username,
          password: cred.password,
          confidence: cred.confidence,
          testedUrl: device.xaddr,
          authType: 'digest' as const
        });
      } catch (error) {
        // Credenciales inválidas, continuar con el siguiente intento
        continue;
      }
    }
    
    return credentials;
  }

  private async detectCapabilities(
    device: onvif.Device,
    manufacturer: string
  ) {
    try {
      const capabilities = await promisify(device.getCapabilities).call(device);
      
      return {
        resolutions: this.extractResolutions(capabilities),
        codecs: this.extractCodecs(capabilities),
        maxFrameRate: 30, // Valor por defecto
        nightVision: manufacturer.toLowerCase().includes('hikvision') || 
                    manufacturer.toLowerCase().includes('dahua'),
        motionDetection: true, // Asumir soporte
        audioSupport: false, // Verificar en capacidades reales
        ptzSupport: capabilities.PTZ !== undefined,
        onvifVersion: '2.0', // Valor por defecto
        profiles: [],
        manufacturerFeatures: {}
      };
    } catch (error) {
      this.logger.warn('No se pudieron detectar capacidades', { 
        error: error instanceof Error ? error.message : String(error) 
      });
      
      // Devolver capacidades por defecto
      return {
        resolutions: ['1920x1080', '1280x720'],
        codecs: ['H.264'],
        maxFrameRate: 15,
        nightVision: false,
        motionDetection: false,
        audioSupport: false,
        ptzSupport: false,
        onvifVersion: '1.0',
        profiles: [],
        manufacturerFeatures: {}
      };
    }
  }

  private async testRTSPConnection(rtspUrl: string): Promise<boolean> {
    return new Promise((resolve) => {
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
          this.logger.debug('Error en ffprobe', { error: errorOutput });
          resolve(false);
        }
      });
      
      // Timeout después de 10 segundos
      setTimeout(() => {
        if (!ffprobe.killed) {
          ffprobe.kill();
          resolve(false);
        }
      }, 10000);
    });
  }

  private async pingCamera(ip: string): Promise<boolean> {
    const cacheKey = `ping_${ip}`;
    const cached = this.pingCache.get(cacheKey);
    
    if (cached && (Date.now() - cached.timestamp < this.PING_CACHE_TTL)) {
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
      
      // Timeout después de 3 segundos
      setTimeout(() => {
        if (!ping.killed) {
          ping.kill();
          this.pingCache.set(cacheKey, { timestamp: Date.now(), result: false });
          resolve(false);
        }
      }, 3000);
    });
  }

  private normalizeManufacturer(manufacturer: string): string {
    if (!manufacturer) return 'generic';
    
    const lower = manufacturer.toLowerCase();
    
    if (lower.includes('hikvision')) return 'hikvision';
    if (lower.includes('dahua')) return 'dahua';
    if (lower.includes('axis')) return 'axis';
    
    return 'generic';
  }

  private determineStreamType(path: string): 'main' | 'sub' | 'mobile' {
    const lowerPath = path.toLowerCase();
    
    if (lowerPath.includes('sub') || lowerPath.includes('102')) return 'sub';
    if (lowerPath.includes('mobile') || lowerPath.includes('103')) return 'mobile';
    
    return 'main';
  }

  private extractResolutionFromPath(path: string): string {
    const resolutionMatch = path.match(/(\d+)x(\d+)/);
    return resolutionMatch ? resolutionMatch[0] : 'auto-detect';
  }

  private extractResolutions(capabilities: any): string[] {
    // Implementar lógica para extraer resoluciones de las capacidades
    return ['1920x1080', '1280x720', '640x480'];
  }

  /**
   * Performs a heartbeat check on a camera to verify its status
   * @param camera Camera object with connection details
   * @returns Promise with the heartbeat result
   */
  public async performHeartbeat(camera: {
    ipAddress: string;
    port?: number;
    username?: string;
    password?: string;
    manufacturer?: string;
  }): Promise<{
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

    // Extraer códecs de video
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

    // Extraer códecs de audio si están disponibles
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

    return codecs.length > 0 ? codecs : ['H.264']; // Valor por defecto
  }

  private calculateConfidence(
    rtspUrls: RTSPUrlInfo[],
    credentials: Array<{ confidence: number }>,
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
