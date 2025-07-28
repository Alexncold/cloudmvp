/**
 * Tipos para el sistema de descubrimiento de cámaras
 */

/**
 * Protocolos de cámara soportados
 */
export type CameraProtocol = 'onvif' | 'rtsp' | 'http' | 'https' | 'rtmp' | 'rtsps' | 'rtmps';

/**
 * Estados de descubrimiento
 */
export type DiscoveryStatus = 'idle' | 'scanning' | 'completed' | 'failed' | 'cancelled';

/**
 * Fases de descubrimiento
 */
export type DiscoveryPhase = 
  | 'initializing'
  | 'network_scan'
  | 'port_scanning'
  | 'device_identification'
  | 'onvif_discovery'
  | 'rtsp_discovery'
  | 'security_scan'
  | 'finalizing';

/**
 * Niveles de seguridad para el escaneo
 */
export type SecurityLevel = 'basic' | 'standard' | 'paranoid';

/**
 * Información de un dispositivo de cámara descubierto
 */
export interface CameraDevice {
  /** ID único del dispositivo */
  id: string;
  
  /** Dirección IP del dispositivo */
  ip: string;
  
  /** Puerto del servicio */
  port: number;
  
  /** Protocolo utilizado para la conexión */
  protocol: CameraProtocol;
  
  /** Nombre del fabricante */
  manufacturer?: string;
  
  /** Modelo de la cámara */
  model?: string;
  
  /** Versión de firmware */
  firmwareVersion?: string;
  
  /** Nombre del dispositivo */
  name?: string;
  
  /** Ubicación física del dispositivo */
  location?: string;
  
  /** Si el dispositivo requiere autenticación */
  requiresAuth: boolean;
  
  /** Nombre de usuario para autenticación (si es conocido) */
  username?: string;
  
  /** Contraseña para autenticación (si es conocida) */
  password?: string;
  
  /** URL base para acceder a la interfaz web */
  webInterfaceUrl?: string;
  
  /** URL del stream RTSP (si está disponible) */
  streamUrl?: string;
  
  /** Puertos abiertos encontrados */
  openPorts?: number[];
  
  /** Servicios detectados */
  services?: {
    name: string;
    port: number;
    protocol: string;
    secure: boolean;
  }[];
  
  /** Información de seguridad */
  security?: {
    /** Si el dispositivo tiene credenciales por defecto */
    hasDefaultCredentials: boolean;
    
    /** Si la conexión está encriptada */
    isEncrypted: boolean;
    
    /** Vulnerabilidades conocidas */
    vulnerabilities?: Array<{
      id: string;
      name: string;
      severity: 'low' | 'medium' | 'high' | 'critical';
      description: string;
      cve?: string;
      remediation?: string;
    }>;
  };
  
  /** Nivel de confianza en la detección (0-1) */
  confidence: number;
  
  /** Fecha y hora del último descubrimiento */
  lastSeen: Date;
  
  /** Metadatos adicionales */
  metadata?: Record<string, any>;
}

/**
 * Estado de progreso del descubrimiento
 */
export interface DiscoveryProgress {
  /** ID de la tarea de descubrimiento */
  taskId: string;
  
  /** ID de sesión del usuario */
  sessionId: string;
  
  /** Estado actual */
  status: DiscoveryStatus;
  
  /** Fase actual del descubrimiento */
  phase: DiscoveryPhase;
  
  /** Progreso general (0-100) */
  progress: number;
  
  /** Mensaje de estado actual */
  message: string;
  
  /** Tiempo estimado restante en segundos */
  eta?: number;
  
  /** Dispositivos encontrados hasta el momento */
  devicesFound: number;
  
  /** Dirección IP o rango que se está escaneando actualmente */
  currentTarget?: string;
  
  /** Advertencias generadas durante el escaneo */
  warnings?: string[];
  
  /** Errores encontrados durante el escaneo */
  errors?: Array<{
    code: string;
    message: string;
    target?: string;
    timestamp: Date;
  }>;
  
  /** Estadísticas del escaneo */
  stats?: {
    startTime: Date;
    endTime?: Date;
    ipsScanned: number;
    portsScanned: number;
    devicesIdentified: number;
    vulnerabilitiesFound: number;
  };
}

/**
 * Parámetros para iniciar un nuevo descubrimiento
 */
export interface DiscoveryOptions {
  /** ID de usuario que inicia el descubrimiento */
  userId: string;
  
  /** ID de sesión del usuario */
  sessionId: string;
  
  /** Rangos de red a escanear (ej. ["192.168.1.0/24"]) */
  networkRanges: string[];
  
  /** Nivel de seguridad para el escaneo */
  securityLevel?: SecurityLevel;
  
  /** Protocolos a escanear */
  protocols?: CameraProtocol[];
  
  /** Rangos de puertos a escanear */
  portRanges?: Array<[number, number]>;
  
  /** Tiempo máximo de espera en milisegundos */
  timeout?: number;
  
  /** Número máximo de hilos de escaneo en paralelo */
  maxThreads?: number;
  
  /** Si se debe verificar credenciales por defecto */
  checkDefaultCredentials?: boolean;
  
  /** Si se debe realizar un escaneo de vulnerabilidades */
  scanForVulnerabilities?: boolean;
  
  /** Metadatos adicionales */
  metadata?: Record<string, any>;
}

/**
 * Resultado de un trabajo de descubrimiento
 */
export interface DiscoveryResult {
  /** ID de la tarea */
  taskId: string;
  
  /** ID de sesión del usuario */
  sessionId: string;
  
  /** Estado final */
  status: 'completed' | 'failed' | 'cancelled';
  
  /** Fecha y hora de inicio */
  startTime: Date;
  
  /** Fecha y hora de finalización */
  endTime: Date;
  
  /** Duración total en milisegundos */
  duration: number;
  
  /** Dispositivos encontrados */
  devices: CameraDevice[];
  
  /** Estadísticas del escaneo */
  stats: {
    totalDevices: number;
    devicesWithDefaultCredentials: number;
    devicesWithVulnerabilities: number;
    totalVulnerabilities: number;
    vulnerabilitiesBySeverity: {
      low: number;
      medium: number;
      high: number;
      critical: number;
    };
  };
  
  /** Errores encontrados (si los hay) */
  errors?: Array<{
    code: string;
    message: string;
    target?: string;
    timestamp: Date;
  }>;
  
  /** Advertencias generadas durante el escaneo */
  warnings?: string[];
}
