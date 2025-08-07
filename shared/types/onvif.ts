/**
 * Shared type definitions for ONVIF camera functionality
 * 
 * These types are used across both frontend and backend to ensure type safety
 * and consistency in camera-related operations.
 */

// Local type definitions to avoid circular dependencies
import type { CommonCredential } from '../../backend/src/utils/camera-config-database';

/** Represents the type of video stream */
export type StreamType = 'main' | 'sub' | 'mobile' | 'snapshot' | 'event';

/** Authentication types supported by ONVIF cameras */
export type AuthType = 'basic' | 'digest' | 'none' | 'wsse';

/** Video codec types */
export type VideoCodec = 'H.264' | 'H.265' | 'MJPEG' | 'MPEG4' | 'JPEG' | 'H.263' | 'G.711' | 'G.726' | 'G.722' | 'AAC' | 'PCM' | 'G.729' | string;

/**
 * Represents the capabilities of an ONVIF camera
 */
export interface CameraCapabilities {
  /** Whether the camera supports video streaming */
  streaming: boolean;
  /** Whether the camera supports PTZ (Pan-Tilt-Zoom) */
  ptz: boolean;
  /** Whether the camera has audio capabilities */
  audio: boolean;
  /** Whether the camera supports motion detection */
  motionDetection: boolean;
  /** Whether the camera supports video analytics */
  analytics: boolean;
  /** Whether the camera has night vision capabilities */
  nightVision: boolean;
  /** Whether the camera supports events */
  events: boolean;
  /** Whether the camera supports snapshots */
  snapshots: boolean;
  /** Whether the camera supports local recording */
  recording: boolean;
  /** Additional vendor-specific capabilities */
  [key: string]: boolean | string | number | undefined;
}

/**
 * Represents a discovered ONVIF camera on the network
 */
export interface DiscoveredCamera {
  /** IP address of the discovered camera */
  ip: string;
  /** Port number for ONVIF services (default: 80) */
  port: number;
  /** Camera manufacturer (e.g., 'Hikvision', 'Dahua') */
  manufacturer: string;
  /** Camera model name */
  model: string;
  /** Firmware version if available */
  firmware?: string;
  /** Base URL for ONVIF device service */
  onvifUrl: string;
  /** List of discovered RTSP stream URLs */
  rtspUrls: RTSPUrlInfo[];
  /** Suggested credentials that might work with this camera */
  suggestedCredentials: SuggestedCredential[];
  /** Detected capabilities of the camera */
  capabilities: CameraCapabilities;
  /** Confidence level (0-1) of the discovery accuracy */
  confidence: number;
  /** Timestamp of when the camera was discovered */
  discoveredAt: Date;
  /** Additional metadata about the discovery */
  metadata?: {
    /** Whether this camera is currently online */
    online?: boolean;
    /** Any warnings or notes about this discovery */
    notes?: string[];
    /** Vendor-specific discovery data */
    [key: string]: any;
  };
}

/**
 * Information about an RTSP stream URL provided by an ONVIF camera
 */
export interface RTSPUrlInfo {
  /** The complete RTSP URL */
  url: string;
  /** Type of the stream (main, sub, mobile, etc.) */
  streamType: StreamType;
  /** Resolution of the stream (e.g., '1920x1080') or 'auto-detect' */
  resolution: string;
  /** Confidence level (0-1) that this is a valid stream */
  confidence: number;
  /** Whether this URL has been tested and verified to work */
  tested: boolean;
  /** Authentication type required for this stream */
  authType?: AuthType;
  /** Bitrate in kbps if known */
  bitrate?: number;
  /** Framerate in fps if known */
  framerate?: number;
  /** Video codec used by this stream */
  codec?: VideoCodec;
  /** Source of this URL (how it was discovered) */
  source?: 'manufacturer' | 'common' | 'auto-detected' | 'user-provided';
  /** Additional metadata about the stream */
  metadata?: {
    /** Whether this is the default stream */
    isDefault?: boolean;
    /** Whether this stream is encrypted */
    encrypted?: boolean;
    /** Any additional vendor-specific properties */
    [key: string]: any;
  };
}

/**
 * Represents a set of credentials that can be used to authenticate with a camera
 */
export interface SuggestedCredential extends CommonCredential {
  /** The URL that was successfully tested with these credentials */
  testedUrl: string;
  /** Authentication type that worked with these credentials */
  authType: AuthType;
  /** When these credentials were last tested */
  lastTested?: Date;
  /** Whether these credentials worked successfully */
  success?: boolean;
  /** Any error message if authentication failed */
  error?: string;
}

/**
 * Result of validating a camera's configuration
 */
export interface ValidationResult {
  /** Whether the configuration is valid */
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

/**
 * Result of a camera heartbeat/status check
 */
export interface HeartbeatResult {
  /** ID of the camera being checked */
  cameraId: number;
  /** Overall status (true if all checks passed) */
  overall: boolean;
  /** Whether the camera responded to ping */
  ping: boolean;
  /** Whether ONVIF service is responding */
  onvif: boolean;
  /** Whether at least one RTSP stream is accessible */
  rtsp: boolean;
  /** Timestamp of the check */
  timestamp: Date;
  /** Detailed results of the heartbeat check */
  details: {
    /** Error message if ping failed */
    pingError?: string;
    /** Error message if ONVIF check failed */
    onvifError?: string;
    /** Error message if RTSP check failed */
    rtspError?: string;
    /** List of tested RTSP URLs with their status */
    rtspUrls?: Array<RTSPUrlInfo & { 
      /** Whether this URL was tested successfully */
      tested: boolean;
      /** Error message if testing failed */
      error?: string; 
    }>;
    /** Generic error message if available */
    error?: string;
    /** Additional diagnostic information */
    [key: string]: any;
  };
}

/**
 * Options for camera discovery
 */
export interface CameraDiscoveryOptions {
  /** Timeout in milliseconds for discovery (default: 10000) */
  timeout?: number;
  /** Whether to automatically add discovered cameras to the system */
  autoAdd?: boolean;
  /** Specific IP range to scan (e.g., '192.168.1.1-255') */
  ipRange?: string;
  /** Ports to scan (default: [80, 8080, 8000, 8899]) */
  ports?: number[];
  /** Whether to perform deep discovery (slower but more thorough) */
  deepDiscovery?: boolean;
  /** Additional discovery options */
  [key: string]: any;
}

/**
 * Options for connecting to a camera
 */
export interface CameraConnectionOptions {
  /** Camera IP address or hostname */
  ip: string;
  /** Camera port number */
  port: number;
  /** Username for authentication */
  username: string;
  /** Password for authentication */
  password: string;
  /** Custom RTSP path (if not using auto-detection) */
  rtspPath?: string;
  /** Whether to validate the connection immediately */
  validate?: boolean;
  /** Timeout for connection attempts in milliseconds */
  timeout?: number;
  /** Additional connection parameters */
  params?: {
    /** ONVIF service path (default: '/onvif/device_service') */
    onvifPath?: string;
    /** RTSP transport protocol (tcp/udp) */
    rtspTransport?: 'tcp' | 'udp' | 'auto';
    /** Additional vendor-specific parameters */
    [key: string]: any;
  };
}
