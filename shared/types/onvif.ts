import { CameraCapabilities, CommonCredential } from '../../backend/src/utils/camera-config-database';

export interface DiscoveredCamera {
  ip: string;
  port: number;
  manufacturer: string;
  model: string;
  firmware?: string;
  onvifUrl: string;
  rtspUrls: RTSPUrlInfo[];
  suggestedCredentials: SuggestedCredential[];
  capabilities: CameraCapabilities;
  confidence: number; // 0-1
  discoveredAt: Date;
}

export interface RTSPUrlInfo {
  url: string;
  streamType: 'main' | 'sub' | 'mobile';
  resolution: string; // '1920x1080' | 'auto-detect'
  confidence: number;
}

export interface SuggestedCredential extends CommonCredential {
  testedUrl: string;
  authType: 'basic' | 'digest';
}

export interface ValidationResult {
  valid: boolean;
  onvifSupport: boolean;
  rtspSupport: boolean;
  detectedRtspUrl: string;
  manufacturer: string;
  model: string;
  firmware: string;
  confidence: number;
  validatedAt: Date;
  error?: string;
}

export interface HeartbeatResult {
  cameraId: number;
  overall: boolean;
  ping: boolean;
  onvif: boolean;
  rtsp: boolean;
  timestamp: Date;
  error?: string;
}

export interface CameraDiscoveryOptions {
  timeout?: number;
  autoAdd?: boolean;
}

export interface CameraConnectionOptions {
  ip: string;
  port: number;
  username: string;
  password: string;
  rtspPath?: string;
}
