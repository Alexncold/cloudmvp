declare module 'node-onvif' {
  export interface DeviceOptions {
    xaddr?: string;
    user?: string;
    pass?: string;
    port?: number;
    timeout?: number;
    hostname?: string;
    username?: string;
    password?: string;
  }

  export interface DeviceInfo {
    manufacturer: string;
    model: string;
    firmware: string;
    serial: string;
    hardware: string;
  }

  export interface NetworkInterface {
    name: string;
    hwaddr: string;
    mtu: number;
    addresses: {
      address: string;
      prefix: number;
    }[];
  }

  export interface PTZNode {
    Name: string;
    [key: string]: any;
  }

  export interface PTZPreset {
    token: string;
    name: string;
    [key: string]: any;
  }

  export interface VideoSource {
    token: string;
    $: {
      token: string;
      Framerate: string;
      Resolution: {
        Width: number;
        Height: number;
      };
      DayNight?: string;
      InfraredCutFilter?: string;
      [key: string]: any;
    };
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
