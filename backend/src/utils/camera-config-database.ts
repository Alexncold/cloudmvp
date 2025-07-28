import { Logger } from '../utils/logger';

export interface CommonCredential {
  username: string;
  password: string;
  confidence: number;
}

export interface ManufacturerConfig {
  name: string;
  confidence: number;
  defaultPort: number;
  rtspPaths: string[];
  commonCredentials: CommonCredential[];
  specificFeatures: {
    nightVision: boolean;
    motionDetection: boolean;
    smartDetection: boolean;
    audioSupport: boolean;
  };
  onvifPath: string;
  httpPort: number;
  rtspPort: number;
}

export class CameraConfigDatabase {
  private static readonly MANUFACTURER_CONFIGS: Record<string, ManufacturerConfig> = {
    'hikvision': {
      name: 'Hikvision',
      confidence: 0.9,
      defaultPort: 80,
      rtspPaths: [
        '/Streaming/Channels/101',        // Main stream
        '/Streaming/Channels/102',        // Sub stream
        '/ISAPI/Streaming/channels/101/picture', // Snapshot
      ],
      commonCredentials: [
        { username: 'admin', password: '12345', confidence: 0.8 },
        { username: 'admin', password: 'admin', confidence: 0.7 },
        { username: 'admin', password: '', confidence: 0.6 },
        { username: 'root', password: '12345', confidence: 0.5 }
      ],
      specificFeatures: {
        nightVision: true,
        motionDetection: true,
        smartDetection: true,
        audioSupport: true
      },
      onvifPath: '/onvif/device_service',
      httpPort: 80,
      rtspPort: 554
    },
    
    'dahua': {
      name: 'Dahua',
      confidence: 0.9,
      defaultPort: 80,
      rtspPaths: [
        '/cam/realmonitor?channel=1&subtype=0',  // Main stream
        '/cam/realmonitor?channel=1&subtype=1',  // Sub stream
        '/cam/snapshot',                         // Snapshot
      ],
      commonCredentials: [
        { username: 'admin', password: 'admin', confidence: 0.8 },
        { username: 'admin', password: '123456', confidence: 0.7 },
        { username: 'admin', password: '', confidence: 0.6 },
        { username: 'user', password: 'user', confidence: 0.4 }
      ],
      specificFeatures: {
        nightVision: true,
        motionDetection: true,
        smartDetection: true,
        audioSupport: true
      },
      onvifPath: '/onvif/device_service',
      httpPort: 80,
      rtspPort: 554
    },
    
    'axis': {
      name: 'Axis',
      confidence: 0.85,
      defaultPort: 80,
      rtspPaths: [
        '/axis-media/media.amp',
        '/axis-media/media.amp?resolution=1920x1080',
        '/axis-media/media.amp?resolution=640x480',
      ],
      commonCredentials: [
        { username: 'root', password: 'pass', confidence: 0.7 },
        { username: 'admin', password: 'admin', confidence: 0.6 },
        { username: 'root', password: '', confidence: 0.5 }
      ],
      specificFeatures: {
        nightVision: true,
        motionDetection: true,
        smartDetection: false,
        audioSupport: true
      },
      onvifPath: '/onvif/device_service',
      httpPort: 80,
      rtspPort: 554
    },
    
    'generic': {
      name: 'Generic',
      confidence: 0.3,
      defaultPort: 80,
      rtspPaths: [
        '/stream1',
        '/live',
        '/video',
        '/cam',
        '/stream'
      ],
      commonCredentials: [
        { username: 'admin', password: 'admin', confidence: 0.5 },
        { username: 'admin', password: '12345', confidence: 0.4 },
        { username: 'admin', password: '', confidence: 0.3 },
        { username: 'user', password: 'user', confidence: 0.2 }
      ],
      specificFeatures: {
        nightVision: false,
        motionDetection: false,
        smartDetection: false,
        audioSupport: false
      },
      onvifPath: '/onvif/device_service',
      httpPort: 80,
      rtspPort: 554
    }
  };

  private logger: Logger;

  constructor() {
    this.logger = new Logger('CameraConfigDatabase');
  }

  getManufacturerConfig(manufacturer: string): ManufacturerConfig {
    if (!manufacturer) {
      this.logger.warn('No manufacturer provided, using generic config');
      return this.MANUFACTURER_CONFIGS['generic'];
    }
    
    const normalized = manufacturer.toLowerCase();
    const config = this.MANUFACTURER_CONFIGS[normalized] || this.MANUFACTURER_CONFIGS['generic'];
    
    if (normalized !== 'generic' && config === this.MANUFACTURER_CONFIGS['generic']) {
      this.logger.debug(`No specific config found for manufacturer: ${manufacturer}, using generic config`);
    }
    
    return config;
  }

  getAllSupportedManufacturers(): string[] {
    return Object.keys(this.MANUFACTURER_CONFIGS).filter(key => key !== 'generic');
  }

  getCommonCredentials(): CommonCredential[] {
    const allCredentials = new Map<string, CommonCredential>();
    
    Object.values(CameraConfigDatabase.MANUFACTURER_CONFIGS).forEach(config => {
      config.commonCredentials.forEach(cred => {
        const key = `${cred.username}:${cred.password}`;
        if (!allCredentials.has(key) || (allCredentials.get(key)?.confidence || 0) < cred.confidence) {
          allCredentials.set(key, cred);
        }
      });
    });
    
    return Array.from(allCredentials.values())
      .sort((a, b) => b.confidence - a.confidence);
  }
}
