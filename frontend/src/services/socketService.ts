import { io, Socket } from 'socket.io-client';
import { store } from '../store';
import { showNotification } from '../store/notificationSlice';
import { NotificationType } from '../types/notification';

type EventCallback = (data: any) => void;

export class SocketService {
  private static instance: SocketService;
  private socket: Socket | null = null;
  private eventCallbacks: Map<string, Set<EventCallback>> = new Map();
  private reconnectAttempts = 0;
  private maxReconnectAttempts = 5;
  private reconnectDelay = 1000; // 1 segundo
  private isConnected = false;
  private connectionPromise: Promise<void> | null = null;

  private constructor() {
    this.initializeSocket();
  }

  public static getInstance(): SocketService {
    if (!SocketService.instance) {
      SocketService.instance = new SocketService();
    }
    return SocketService.instance;
  }

  private getAuthToken(): string | null {
    const state = store.getState();
    return state.auth.token || null;
  }

  private initializeSocket(): void {
    if (this.socket?.connected) {
      return;
    }

    const socketUrl = import.meta.env.VITE_SOCKET_URL || 'http://localhost:3001';
    const token = this.getAuthToken();

    if (!token) {
      console.warn('No authentication token available for socket connection');
      return;
    }

    this.socket = io(socketUrl, {
      path: '/socket.io',
      transports: ['websocket'],
      autoConnect: false,
      reconnection: true,
      reconnectionAttempts: this.maxReconnectAttempts,
      reconnectionDelay: this.reconnectDelay,
      reconnectionDelayMax: 5000,
      timeout: 20000,
      auth: { token },
      query: {
        clientType: 'web',
        version: import.meta.env.VITE_APP_VERSION || '1.0.0',
      },
    });

    this.setupEventListeners();
    this.connect();
  }

  private setupEventListeners(): void {
    if (!this.socket) return;

    this.socket.on('connect', () => {
      console.log('Socket connected:', this.socket?.id);
      this.isConnected = true;
      this.reconnectAttempts = 0;
      this.emitEvent('socket:connected', { socketId: this.socket?.id });
      store.dispatch(
        showNotification({
          type: NotificationType.Info,
          message: 'Conexión establecida con el servidor',
          autoHide: true,
        })
      );
    });

    this.socket.on('disconnect', (reason) => {
      console.log('Socket disconnected:', reason);
      this.isConnected = false;
      this.emitEvent('socket:disconnected', { reason });
      
      if (reason === 'io server disconnect') {
        // Reconexión forzada si el servidor nos desconectó
        this.socket?.connect();
      }
    });

    this.socket.on('connect_error', (error) => {
      console.error('Socket connection error:', error);
      this.emitEvent('socket:error', { error: error.message });
      
      // Mostrar notificación solo para errores críticos
      if (error.message.includes('authentication') || error.message.includes('401')) {
        store.dispatch(
          showNotification({
            type: NotificationType.Error,
            message: 'Error de autenticación en la conexión',
            autoHide: false,
          })
        );
      }
    });

    this.socket.on('reconnect_attempt', (attemptNumber) => {
      console.log(`Reconnection attempt ${attemptNumber}/${this.maxReconnectAttempts}`);
      this.reconnectAttempts = attemptNumber;
      this.emitEvent('socket:reconnecting', { attempt: attemptNumber });
    });

    this.socket.on('reconnect_failed', () => {
      console.error('Failed to reconnect to the server');
      this.emitEvent('socket:reconnect_failed');
      store.dispatch(
        showNotification({
          type: NotificationType.Error,
          message: 'No se pudo reconectar con el servidor',
          autoHide: false,
        })
      );
    });

    // Manejar eventos personalizados registrados dinámicamente
    this.socket.onAny((eventName: string, ...args: any[]) => {
      this.emitEvent(eventName, ...args);
    });
  }

  public async connect(): Promise<void> {
    if (this.connectionPromise) {
      return this.connectionPromise;
    }

    if (this.isConnected) {
      return Promise.resolve();
    }

    this.connectionPromise = new Promise((resolve, reject) => {
      if (!this.socket) {
        this.initializeSocket();
      }

      if (!this.socket) {
        return reject(new Error('Socket no inicializado'));
      }

      const onConnect = () => {
        this.socket?.off('connect_error', onError);
        this.connectionPromise = null;
        resolve();
      };

      const onError = (error: Error) => {
        this.socket?.off('connect', onConnect);
        this.connectionPromise = null;
        reject(error);
      };

      this.socket.once('connect', onConnect);
      this.socket.once('connect_error', onError);
      this.socket.connect();
    });

    return this.connectionPromise;
  }

  public disconnect(): void {
    if (this.socket) {
      this.socket.disconnect();
      this.isConnected = false;
      this.connectionPromise = null;
    }
  }

  public on(eventName: string, callback: EventCallback): () => void {
    if (!this.eventCallbacks.has(eventName)) {
      this.eventCallbacks.set(eventName, new Set());
    }
    
    const callbacks = this.eventCallbacks.get(eventName)!;
    callbacks.add(callback);

    // Devolver función para cancelar la suscripción
    return () => {
      callbacks.delete(callback);
      if (callbacks.size === 0) {
        this.eventCallbacks.delete(eventName);
      }
    };
  }

  public off(eventName: string, callback: EventCallback): void {
    const callbacks = this.eventCallbacks.get(eventName);
    if (callbacks) {
      callbacks.delete(callback);
      if (callbacks.size === 0) {
        this.eventCallbacks.delete(eventName);
      }
    }
  }

  private emitEvent(eventName: string, ...args: any[]): void {
    const callbacks = this.eventCallbacks.get(eventName);
    if (callbacks) {
      callbacks.forEach((callback) => {
        try {
          callback(...args);
        } catch (error) {
          console.error(`Error en el manejador del evento ${eventName}:`, error);
        }
      });
    }
  }

  public emit(eventName: string, data: any = {}, ack?: (response: any) => void): void {
    if (!this.isConnected || !this.socket) {
      console.warn(`Intento de emitir evento ${eventName} sin conexión establecida`);
      this.connect().then(() => {
        this.socket?.emit(eventName, data, ack);
      });
      return;
    }

    // Añadir metadatos a cada mensaje
    const message = {
      ...data,
      _meta: {
        timestamp: new Date().toISOString(),
        clientId: this.socket.id,
      },
    };

    if (ack) {
      this.socket.emit(eventName, message, ack);
    } else {
      this.socket.emit(eventName, message);
    }
  }

  // Métodos específicos para el descubrimiento de cámaras
  public startDiscovery(options: any = {}): Promise<{ success: boolean; message: string; sessionId?: string }> {
    return new Promise((resolve) => {
      this.emit('discovery:start', options, (response: any) => {
        resolve(response);
      });
    });
  }

  public cancelDiscovery(sessionId: string): Promise<{ success: boolean; message: string }> {
    return new Promise((resolve) => {
      this.emit('discovery:cancel', { sessionId }, (response: any) => {
        resolve(response);
      });
    });
  }

  public getDiscoveryStatus(sessionId: string): Promise<{ success: boolean; status?: any; error?: string }> {
    return new Promise((resolve) => {
      this.emit('discovery:status', { sessionId }, (response: any) => {
        resolve(response);
      });
    });
  }

  // Métodos para suscribirse a eventos de descubrimiento
  public onDiscoveryProgress(callback: (progress: any) => void): () => void {
    return this.on('discovery:progress', callback);
  }

  public onDeviceFound(callback: (device: any) => void): () => void {
    return this.on('discovery:device', callback);
  }

  public onDiscoveryComplete(callback: (result: any) => void): () => void {
    return this.on('discovery:complete', callback);
  }

  public onDiscoveryError(callback: (error: any) => void): () => void {
    return this.on('discovery:error', callback);
  }

  // Métodos de utilidad
  public getSocketId(): string | undefined {
    return this.socket?.id;
  }

  public isSocketConnected(): boolean {
    return this.isConnected && this.socket?.connected === true;
  }

  // Reiniciar la conexión (útil para cuando cambia el token de autenticación)
  public async reconnectWithNewToken(token: string): Promise<void> {
    this.disconnect();
    // Esperar un momento antes de reconectar
    await new Promise(resolve => setTimeout(resolve, 500));
    this.initializeSocket();
    return this.connect();
  }
}

// Exportar una instancia global del servicio
export const socketService = SocketService.getInstance();

export default socketService;
