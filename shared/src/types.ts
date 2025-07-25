// Tipos compartidos entre frontend y backend

export interface User {
  id: string;
  email: string;
  name?: string;
  avatar?: string;
  role: 'admin' | 'user';
  createdAt: string;
  updatedAt: string;
}

export interface Camera {
  id: string;
  name: string;
  ip: string;
  port: number;
  username?: string;
  password?: string;
  rtspUrl: string;
  isActive: boolean;
  isRecording: boolean;
  lastSeen?: string;
  createdAt: string;
  updatedAt: string;
}

export interface Recording {
  id: string;
  cameraId: string;
  startTime: string;
  endTime?: string;
  duration?: number; // en segundos
  filePath?: string;
  fileSize?: number; // en bytes
  status: 'recording' | 'completed' | 'failed' | 'processing';
  createdAt: string;
  updatedAt: string;
}

export interface ApiResponse<T = any> {
  success: boolean;
  data?: T;
  error?: {
    code: string;
    message: string;
    details?: any;
  };
  timestamp: string;
}

// Tipos para autenticación
export interface LoginRequest {
  email: string;
  password: string;
}

export interface LoginResponse {
  user: Omit<User, 'password'>;
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
}

export interface RegisterRequest {
  email: string;
  password: string;
  name: string;
}

// Tipos para WebSocket
export enum WsEventType {
  CAMERA_STATUS_CHANGED = 'camera:status_changed',
  RECORDING_STARTED = 'recording:started',
  RECORDING_STOPPED = 'recording:stopped',
  MOTION_DETECTED = 'motion:detected',
  SYSTEM_ALERT = 'system:alert',
}

export interface WsMessage<T = any> {
  event: WsEventType;
  data: T;
  timestamp: string;
}

// Tipos para configuración de la aplicación
export interface AppConfig {
  maxRecordingDuration: number; // en segundos
  motionDetection: {
    enabled: boolean;
    sensitivity: number; // 1-100
    regions: Array<{
      x: number;
      y: number;
      width: number;
      height: number;
    }>;
  };
  storage: {
    maxStorageGB: number;
    retentionDays: number;
    autoDelete: boolean;
  };
}

// Tipos para paginación
export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  page: number;
  limit: number;
  totalPages: number;
}

export interface PaginationParams {
  page?: number;
  limit?: number;
  sortBy?: string;
  sortOrder?: 'asc' | 'desc';
}
