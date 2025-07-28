import { Socket } from 'socket.io';
import { verify } from 'jsonwebtoken';
import { logger } from '../utils/logger';
import { User } from '../models/User';
import { UnauthorizedError, ForbiddenError } from '../errors';

// Extender la interfaz de Socket para incluir información de usuario
declare module 'socket.io' {
  interface Socket {
    user?: {
      id: string;
      email: string;
      role: string;
      permissions: string[];
    };
  }
}

/**
 * Middleware para autenticar conexiones WebSocket con JWT
 */
export const socketAuth = async (socket: Socket, next: (err?: Error) => void) => {
  try {
    // Obtener el token del handshake o de los query parameters
    const token = 
      socket.handshake.auth?.token || 
      (socket.handshake.query?.token as string)?.split(' ')[1];

    if (!token) {
      logger.warn('Intento de conexión WebSocket sin token de autenticación');
      return next(new UnauthorizedError('Token de autenticación no proporcionado'));
    }

    // Verificar el token JWT
    const decoded = verify(token, process.env.JWT_SECRET!) as {
      userId: string;
      email: string;
      role: string;
      permissions: string[];
      iat: number;
      exp: number;
    };

    // Verificar si el token está a punto de expirar (menos de 5 minutos)
    const now = Math.floor(Date.now() / 1000);
    const expiresIn = decoded.exp - now;
    
    if (expiresIn < 300) { // 5 minutos
      logger.warn(`Token del usuario ${decoded.email} está a punto de expirar (expira en ${expiresIn} segundos)`);
      // Se podría emitir un evento para que el frontend renueve el token
      socket.emit('auth:token_expiring', { expiresIn });
    }

    // Verificar si el usuario existe y está activo en la base de datos
    const user = await User.findByPk(decoded.userId, {
      attributes: ['id', 'email', 'role', 'isActive', 'lastLoginAt'],
      raw: true
    });

    if (!user || !user.isActive) {
      logger.warn(`Usuario no encontrado o inactivo: ${decoded.email}`);
      return next(new ForbiddenError('Usuario no autorizado o cuenta inactiva'));
    }

    // Adjuntar información del usuario al socket
    socket.user = {
      id: user.id,
      email: user.email,
      role: user.role,
      permissions: decoded.permissions || []
    };

    // Unir al usuario a una sala privada
    socket.join(`user:${user.id}`);
    
    // Unir a salas adicionales según el rol
    if (user.role === 'admin') {
      socket.join('admin');
    }
    
    // Registrar la conexión exitosa
    logger.info(`Usuario autenticado vía WebSocket: ${user.email} (${user.role})`);
    
    next();
  } catch (error) {
    logger.error('Error de autenticación WebSocket:', error);
    
    if (error instanceof UnauthorizedError || error instanceof ForbiddenError) {
      return next(error);
    }
    
    // Manejar diferentes tipos de errores de JWT
    if (error.name === 'TokenExpiredError') {
      return next(new UnauthorizedError('Token expirado'));
    }
    
    if (error.name === 'JsonWebTokenError') {
      return next(new UnauthorizedError('Token inválido'));
    }
    
    next(new UnauthorizedError('Error de autenticación'));
  }
};

/**
 * Middleware para verificar roles de usuario
 */
export const socketRoleAuth = (roles: string | string[]) => {
  return (socket: Socket, next: (err?: Error) => void) => {
    if (!socket.user) {
      return next(new UnauthorizedError('No autenticado'));
    }
    
    const userRoles = Array.isArray(socket.user.role) 
      ? socket.user.role 
      : [socket.user.role];
    
    const requiredRoles = Array.isArray(roles) ? roles : [roles];
    const hasRole = requiredRoles.some(role => userRoles.includes(role));
    
    if (!hasRole) {
      logger.warn(`Acceso denegado: el usuario ${socket.user.email} no tiene el rol requerido (${requiredRoles.join(', ')})`);
      return next(new ForbiddenError('No tiene permisos suficientes'));
    }
    
    next();
  };
};

/**
 * Middleware para verificar permisos específicos
 */
export const socketPermissionAuth = (permission: string) => {
  return (socket: Socket, next: (err?: Error) => void) => {
    if (!socket.user) {
      return next(new UnauthorizedError('No autenticado'));
    }
    
    const hasPermission = socket.user.permissions.includes(permission);
    
    if (!hasPermission) {
      logger.warn(`Acceso denegado: el usuario ${socket.user.email} no tiene el permiso requerido (${permission})`);
      return next(new ForbiddenError('No tiene permisos suficientes'));
    }
    
    next();
  };
};

/**
 * Middleware para registrar eventos de conexión/desconexión
 */
export const socketLogger = (socket: Socket, next: (err?: Error) => void) => {
  const userInfo = socket.user ? `usuario ${socket.user.email}` : 'usuario no autenticado';
  
  logger.info(`Nueva conexión WebSocket: ${socket.id} (${userInfo})`);
  
  // Registrar eventos de desconexión
  socket.on('disconnect', (reason) => {
    logger.info(`Conexión WebSocket cerrada: ${socket.id} (${userInfo}) - Razón: ${reason}`);
  });
  
  // Manejar errores de socket
  socket.on('error', (error) => {
    logger.error(`Error en la conexión WebSocket ${socket.id} (${userInfo}):`, error);
  });
  
  next();
};
