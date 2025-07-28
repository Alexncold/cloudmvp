import { useEffect, useRef, useCallback, useState } from 'react';
import { socketService, EventCallback } from '../services/socketService';
import { useAppSelector } from '../store/hooks';
import { selectIsAuthenticated, selectToken } from '../store/authSlice';

/**
 * Hook personalizado para manejar la conexión de sockets de manera segura
 * @param events - Objeto con eventos a suscribir { eventName: callback }
 * @param dependencies - Dependencias para el efecto (opcional)
 * @returns Objeto con utilidades de socket y estado de conexión
 */
export const useSocket = (
  events: Record<string, EventCallback> = {},
  dependencies: any[] = []
) => {
  const isAuthenticated = useAppSelector(selectIsAuthenticated);
  const token = useAppSelector(selectToken);
  const [isConnected, setIsConnected] = useState(socketService.isSocketConnected());
  const cleanupRef = useRef<(() => void)[]>([]);

  // Efecto para manejar la conexión/desconexión basada en la autenticación
  useEffect(() => {
    let mounted = true;

    const handleConnect = () => mounted && setIsConnected(true);
    const handleDisconnect = () => mounted && setIsConnected(false);

    // Suscribirse a eventos de conexión/desconexión
    socketService.on('connect', handleConnect);
    socketService.on('disconnect', handleDisconnect);

    // Conectar si está autenticado
    const connectIfNeeded = async () => {
      if (isAuthenticated && token) {
        try {
          await socketService.connect();
        } catch (error) {
          console.error('Error al conectar el socket:', error);
        }
      } else {
        // Desconectar si no está autenticado
        socketService.disconnect();
        setIsConnected(false);
      }
    };

    connectIfNeeded();

    // Limpieza al desmontar
    return () => {
      mounted = false;
      socketService.off('connect', handleConnect);
      socketService.off('disconnect', handleDisconnect);
      
      // Limpiar todos los manejadores de eventos registrados
      cleanupRef.current.forEach(cleanup => cleanup());
      cleanupRef.current = [];
    };
  }, [isAuthenticated, token]);

  // Efecto para manejar la suscripción a eventos personalizados
  useEffect(() => {
    // Limpiar manejadores anteriores
    cleanupRef.current.forEach(cleanup => cleanup());
    cleanupRef.current = [];

    // Suscribirse a los nuevos eventos
    Object.entries(events).forEach(([eventName, callback]) => {
      const cleanup = socketService.on(eventName, callback);
      cleanupRef.current.push(cleanup);
    });

    // Limpieza al desmontar o cuando cambian las dependencias
    return () => {
      cleanupRef.current.forEach(cleanup => cleanup());
      cleanupRef.current = [];
    };
  }, [...dependencies, isConnected]);

  // Memoizar las funciones de utilidad
  const emit = useCallback((eventName: string, data: any = {}, ack?: (response: any) => void) => {
    if (!isConnected) {
      console.warn(`Intento de emitir evento ${eventName} sin conexión establecida`);
      return;
    }
    socketService.emit(eventName, data, ack);
  }, [isConnected]);

  const getSocketId = useCallback(() => socketService.getSocketId(), []);
  const reconnect = useCallback(() => socketService.connect(), []);
  const disconnect = useCallback(() => socketService.disconnect(), []);

  return {
    isConnected,
    emit,
    on: socketService.on.bind(socketService),
    off: socketService.off.bind(socketService),
    getSocketId,
    reconnect,
    disconnect,
  };
};

/**
 * Hook específico para el descubrimiento de cámaras
 */
export const useDiscoverySocket = () => {
  const [discoveryStatus, setDiscoveryStatus] = useState<{
    isDiscovering: boolean;
    progress: number;
    devices: any[];
    error: string | null;
    sessionId: string | null;
  }>({
    isDiscovering: false,
    progress: 0,
    devices: [],
    error: null,
    sessionId: null,
  });

  // Usar el hook de socket genérico con los manejadores de descubrimiento
  const { isConnected, emit } = useSocket(
    {
      'discovery:progress': (data: { progress: number; scanned: number; total: number }) => {
        setDiscoveryStatus(prev => ({
          ...prev,
          progress: data.progress,
        }));
      },
      'discovery:device': (device: any) => {
        setDiscoveryStatus(prev => ({
          ...prev,
          devices: [...prev.devices, device],
        }));
      },
      'discovery:complete': (data: { sessionId: string; totalDevices: number }) => {
        setDiscoveryStatus(prev => ({
          ...prev,
          isDiscovering: false,
          progress: 100,
          sessionId: data.sessionId,
        }));
      },
      'discovery:error': (error: { message: string }) => {
        setDiscoveryStatus(prev => ({
          ...prev,
          isDiscovering: false,
          error: error.message,
        }));
      },
    },
    [setDiscoveryStatus]
  );

  // Iniciar el descubrimiento
  const startDiscovery = useCallback(
    async (options: any = {}) => {
      setDiscoveryStatus({
        isDiscovering: true,
        progress: 0,
        devices: [],
        error: null,
        sessionId: null,
      });

      try {
        const result = await new Promise<any>((resolve) => {
          emit('discovery:start', options, resolve);
        });

        if (!result.success) {
          throw new Error(result.message || 'Error al iniciar el descubrimiento');
        }

        return result;
      } catch (error) {
        setDiscoveryStatus(prev => ({
          ...prev,
          isDiscovering: false,
          error: error instanceof Error ? error.message : 'Error desconocido',
        }));
        throw error;
      }
    },
    [emit]
  );

  // Cancelar el descubrimiento
  const cancelDiscovery = useCallback(async () => {
    const { sessionId } = discoveryStatus;
    if (!sessionId) return;

    try {
      const result = await new Promise<any>((resolve) => {
        emit('discovery:cancel', { sessionId }, resolve);
      });

      if (!result.success) {
        throw new Error(result.message || 'Error al cancelar el descubrimiento');
      }

      setDiscoveryStatus(prev => ({
        ...prev,
        isDiscovering: false,
        progress: 0,
      }));

      return result;
    } catch (error) {
      console.error('Error al cancelar el descubrimiento:', error);
      throw error;
    }
  }, [emit, discoveryStatus.sessionId]);

  // Obtener el estado actual del descubrimiento
  const getDiscoveryStatus = useCallback(async () => {
    const { sessionId } = discoveryStatus;
    if (!sessionId) return null;

    try {
      const result = await new Promise<any>((resolve) => {
        emit('discovery:status', { sessionId }, resolve);
      });

      if (result.success && result.status) {
        setDiscoveryStatus(prev => ({
          ...prev,
          ...result.status,
        }));
      }

      return result;
    } catch (error) {
      console.error('Error al obtener el estado del descubrimiento:', error);
      throw error;
    }
  }, [emit, discoveryStatus.sessionId]);

  // Limpiar el estado del descubrimiento
  const resetDiscovery = useCallback(() => {
    setDiscoveryStatus({
      isDiscovering: false,
      progress: 0,
      devices: [],
      error: null,
      sessionId: null,
    });
  }, []);

  return {
    ...discoveryStatus,
    isConnected,
    startDiscovery,
    cancelDiscovery,
    getDiscoveryStatus,
    resetDiscovery,
  };
};

export default useSocket;
