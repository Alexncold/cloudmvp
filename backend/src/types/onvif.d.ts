declare module 'node-onvif' {
  export class Device {
    constructor(config: {
      xaddr: string;
      user?: string;
      pass?: string;
      port?: number;
    });

    init(): Promise<void>;
    
    getProfiles(callback: (err: Error | null, data: any) => void): void;
    getProfiles(): Promise<any>;
    
    getAudioSources(callback: (err: Error | null, data: any) => void): void;
    getAudioSources(): Promise<any>;
    
    getVideoEncoderConfiguration(
      options: { ConfigurationToken: string },
      callback: (err: Error | null, data: any) => void
    ): void;
    getVideoEncoderConfiguration(options: { ConfigurationToken: string }): Promise<any>;
    
    getDeviceInformation(callback: (err: Error | null, data: any) => void): void;
    getDeviceInformation(): Promise<any>;
    
    getSystemDateAndTime(callback: (err: Error | null, data: any) => void): void;
    getSystemDateAndTime(): Promise<any>;
    
    getPresets(options: { ProfileToken: string }, callback: (err: Error | null, data: any) => void): void;
    getPresets(options: { ProfileToken: string }): Promise<any>;
    
    getStatus(options: { ProfileToken: string }, callback: (err: Error | null, data: any) => void): void;
    getStatus(options: { ProfileToken: string }): Promise<any>;
    
    getStreamUri(options: { protocol: string; ProfileToken: string }, callback: (err: Error | null, data: any) => void): void;
    getStreamUri(options: { protocol: string; ProfileToken: string }): Promise<any>;
  }

  export function discover(onDiscovery: (device: Device) => void, timeout?: number): Promise<void>;
  
  export interface DiscoveredDevice {
    name: string;
    xaddrs: string[];
    scopes: string[];
    types: string[];
  }
}
