// Type definitions for node-onvif
// Project: https://github.com/futomi/node-onvif
// Definitions by: CloudCam Team <https://github.com/Alexncold/cloudmvp>

declare module 'node-onvif' {
  export interface DeviceOptions {
    /** The XAddr of the device (e.g., 'http://192.168.1.100/onvif/device_service') */
    xaddr?: string;
    /** @deprecated Use username instead */
    user?: string;
    /** @deprecated Use password instead */
    pass?: string;
    /** Port number for the ONVIF service (default: 80) */
    port?: number;
    /** Connection timeout in milliseconds (default: 10000) */
    timeout?: number;
    /** Hostname or IP address of the camera */
    hostname?: string;
    /** Username for authentication */
    username?: string;
    /** Password for authentication */
    password?: string;
  }

  export interface DeviceInfo {
    /** Manufacturer of the device (e.g., 'Hikvision', 'Dahua') */
    manufacturer: string;
    /** Model name of the device */
    model: string;
    /** Firmware version */
    firmware: string;
    /** Serial number of the device */
    serial: string;
    /** Hardware version */
    hardware: string;
    /** Additional metadata */
    [key: string]: any;
  }

  export interface NetworkAddress {
    /** IP address */
    address: string;
    /** Network prefix length (e.g., 24 for 255.255.255.0) */
    prefix: number;
    /** Address type (IPv4/IPv6) */
    type?: 'IPv4' | 'IPv6';
  }

  export interface NetworkInterface {
    /** Interface name (e.g., 'eth0', 'wlan0') */
    name: string;
    /** Hardware (MAC) address */
    hwaddr: string;
    /** Maximum Transmission Unit */
    mtu: number;
    /** List of network addresses */
    addresses: NetworkAddress[];
    /** Interface status (up/down) */
    up?: boolean;
  }

  export interface PTZNode {
    /** Name of the PTZ node */
    Name: string;
    /** Token that uniquely identifies the node */
    token: string;
    /** Supported PTZ capabilities */
    supportedPTZSpaces?: {
      absolutePanTiltPositionSpace?: any[];
      absoluteZoomPositionSpace?: any[];
      relativePanTiltTranslationSpace?: any[];
      relativeZoomTranslationSpace?: any[];
      continuousPanTiltVelocitySpace?: any[];
      continuousZoomVelocitySpace?: any[];
      panTiltSpeedSpace?: any[];
      zoomSpeedSpace?: any[];
    };
    /** Maximum number of presets */
    maximumNumberOfPresets?: number;
    /** Home position support */
    homeSupported?: boolean;
    /** Additional properties */
    [key: string]: any;
  }

  export interface PTZPreset {
    /** Unique identifier for the preset */
    token: string;
    /** User-defined name for the preset */
    name: string;
    /** Optional description of the preset */
    description?: string;
    /** Optional position information */
    position?: {
      pan?: number;
      tilt?: number;
      zoom?: number;
      [key: string]: any;
    };
    /** Additional properties */
    [key: string]: any;
  }

  export interface Resolution {
    /** Frame width in pixels */
    Width: number;
    /** Frame height in pixels */
    Height: number;
    /** Frame rate in frames per second */
    FrameRate?: number;
  }

  export interface VideoSource {
    /** Unique identifier for the video source */
    token: string;
    /** Video source configuration */
    $: {
      token: string;
      /** Frame rate as a string (e.g., '30.0') */
      Framerate: string;
      /** Video resolution */
      Resolution: Resolution;
      /** Day/night mode */
      DayNight?: string;
      /** Infrared cut filter status */
      InfraredCutFilter?: string;
      /** Additional properties */
      [key: string]: any;
    };
    /** Additional properties */
    [key: string]: any;
  }

  export interface EventProperties {
    topicSet: {
      topic: Array<{ $: { name: string } }> | { $: { name: string } };
      [key: string]: any;
    };
    [key: string]: any;
  }

  export interface Device {
    constructor(options: DeviceOptions);
    init(): Promise<void>;
    getDeviceInformation(): Promise<DeviceInfo>;
    getNetworkInterfaces(): Promise<NetworkInterface[]>;
    getSystemDateAndTime(): Promise<any>;
    getCapabilities(): Promise<{
      device: any;
      events: any;
      media: any;
      PTZ?: any;
      [key: string]: any;
    }>;
    getProfiles(): Promise<any>;
    getStreamUri(profileToken: string): Promise<{ uri: string }>;
    getSnapshotUri(profileToken: string): Promise<{ uri: string }>;
    getServices(): Promise<{
      [key: string]: any;
      ptz?: any;
    }>;
    getServiceCapabilities(): Promise<any>;
    getVideoSources(): Promise<VideoSource[]>;
    getVideoSourceConfiguration(profileToken: string): Promise<any>;
    getVideoEncoderConfiguration(profileToken: string): Promise<any>;
    getVideoEncoderConfigurationOptions(profileToken: string): Promise<any>;
    getVideoSourceModes(configurationToken: string): Promise<any>;
    getVideoSourceConfigurationOptions(profileToken: string): Promise<any>;
    getCompatibleVideoAnalyticsConfigurations(profileToken: string): Promise<any>;
    getCompatibleMetadataConfigurations(profileToken: string): Promise<any>;
    getCompatibleAudioSourceConfigurations(profileToken: string): Promise<any>;
    getCompatibleAudioEncoderConfigurations(profileToken: string): Promise<any>;
    getCompatibleVideoSourceConfigurations(profileToken: string): Promise<any>;
    getCompatibleVideoEncoderConfigurations(profileToken: string): Promise<any>;
    getCompatiblePTZConfigurations(profileToken: string): Promise<any>;
    getAnalyticsModules(): Promise<any>;
    getAnalyticsConfigurations(callback: (err: Error | null, data: any) => void): void;
    getEventProperties(): Promise<EventProperties>;
    getNodes(): Promise<PTZNode[]>;
    getPresets(): Promise<PTZPreset[]>;
    getAudioSources(): Promise<any[]>;
    
    // Properties
    hostname: string;
    port: number;
    xaddr: string;
    username?: string;
    password?: string;
    services?: {
      ptz?: any;
      [key: string]: any;
    };
    
    // Additional methods
    getStatus(): Promise<{
      position: {
        x: number;
        y: number;
        z: number;
      };
      moveStatus: string;
      [key: string]: any;
    }>;
    
    absoluteMove(options: {
      x: number;
      y: number;
      zoom?: number;
      speed?: number;
      [key: string]: any;
    }): Promise<void>;
    
    relativeMove(options: {
      x: number;
      y: number;
      zoom?: number;
      speed?: number;
      [key: string]: any;
    }): Promise<void>;
    
    continuousMove(options: {
      x: number;
      y: number;
      zoom?: number;
      timeout?: number;
      [key: string]: any;
    }): Promise<void>;
    
    stop(): Promise<void>;
    
    setPreset(options: {
      presetName: string;
      presetToken?: string;
      [key: string]: any;
    }): Promise<{ presetToken: string }>;
    
    gotoPreset(options: {
      presetToken: string;
      speed?: number;
      [key: string]: any;
    }): Promise<void>;
    
    removePreset(presetToken: string): Promise<void>;
    
    // Event emitter methods
    on(event: string, listener: (...args: any[]) => void): this;
    once(event: string, listener: (...args: any[]) => void): this;
    off(event: string, listener: (...args: any[]) => void): this;
    removeListener(event: string, listener: (...args: any[]) => void): this;
    removeAllListeners(event?: string | symbol): this;
  }

  export class Discover {
    static on(event: 'device', listener: (device: Device) => void): void;
    static on(event: 'error', listener: (error: Error) => void): void;
    static on(event: string, listener: (...args: any[]) => void): void;
    static start(): void;
    static stop(): void;
    static probe(timeout: number, callback: (error: Error | null, devices?: Device[]) => void): void;
    static probe(timeout: number): Promise<Device[]>;
    static socket: any;
  }

  export function discoverThemAll(timeout: number): Promise<Device[]>;
  export function probe(timeout: number): Promise<Device[]>;
  export function createDevice(options: DeviceOptions): Promise<Device>;
  
  // Export Device class directly for use with 'new Device()'
  export const Device: new (options: DeviceOptions) => Device;
}
