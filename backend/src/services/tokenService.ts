import { db } from './db';
import { v4 as uuidv4 } from 'uuid';
import { logger } from '../utils/logger';

// Interfaz para los resultados de las consultas a la base de datos
interface DbRefreshToken {
  id: string;
  user_id: string;
  token: string;
  expires_at: Date | string;
  created_at: Date | string;
  revoked: boolean;
  revoked_at?: Date | string | null;
  replaced_by_token?: string | null;
  created_by_ip?: string;
  user_agent?: string;
}

// Función para mapear un token de la base de datos a la interfaz RefreshToken
const mapDbTokenToRefreshToken = (dbToken: unknown): RefreshToken => {
  const token = dbToken as DbRefreshToken;
  return {
    id: token.id,
    userId: token.user_id,
    token: token.token,
    expiresAt: new Date(token.expires_at),
    createdAt: new Date(token.created_at),
    revoked: token.revoked,
    revokedAt: token.revoked_at ? new Date(token.revoked_at) : null,
    replacedByToken: token.replaced_by_token || null,
    createdByIp: token.created_by_ip,
    userAgent: token.user_agent
  };
};

export interface RefreshToken {
  id: string;
  userId: string;
  token: string;
  expiresAt: Date;
  createdAt: Date;
  revoked: boolean;
  revokedAt?: Date | null;
  replacedByToken?: string | null;
  createdByIp?: string;
  userAgent?: string;
}

export class TokenService {
  // Tiempo de vida de los tokens de actualización (30 días)
  private static readonly REFRESH_TOKEN_LIFETIME_DAYS = 30;

  /**
   * Crea un nuevo token de actualización
   */
  static async createRefreshToken(
    userId: string, 
    ipAddress: string, 
    userAgent: string = ''
  ): Promise<RefreshToken> {
    const tokenId = uuidv4();
    const tokenValue = uuidv4();
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + this.REFRESH_TOKEN_LIFETIME_DAYS);

    try {
      const result = await db.query(
        `INSERT INTO refresh_tokens (
          id, user_id, token, expires_at, created_by_ip, user_agent, created_at, revoked
        ) VALUES ($1, $2, $3, $4, $5, $6, NOW(), false)
        RETURNING *`,
        [tokenId, userId, tokenValue, expiresAt, ipAddress, userAgent]
      );

      if (!result.rows || result.rows.length === 0) {
        throw new Error('No se recibió el token de actualización de la base de datos');
      }

      // Usar la función de mapeo para convertir el resultado de la base de datos
      return mapDbTokenToRefreshToken(result.rows[0]);
    } catch (error: unknown) {
      const errorMessage = error instanceof Error ? error.message : 'Error desconocido al crear token';
      logger.error('Error creating refresh token', { 
        error: errorMessage, 
        userId,
        stack: error instanceof Error ? error.stack : undefined
      });
      throw new Error('No se pudo crear el token de actualización');
    }
  }

  /**
   * Obtiene un token de actualización por su valor
   */
  static async getByToken(token: string): Promise<RefreshToken | null> {
    try {
      const result = await db.query(
        'SELECT * FROM refresh_tokens WHERE token = $1',
        [token]
      );
      
      if (!result.rows || result.rows.length === 0) {
        return null;
      }
      
      // Usar la función de mapeo para convertir el resultado de la base de datos
      return mapDbTokenToRefreshToken(result.rows[0]);
    } catch (error: unknown) {
      const errorMessage = error instanceof Error ? error.message : 'Error desconocido al obtener token';
      logger.error('Error getting refresh token', { 
        error: errorMessage,
        stack: error instanceof Error ? error.stack : undefined
      });
      return null;
    }
  }

  /**
   * Revoca un token de actualización
   */
  static async revokeToken(
    token: string, 
    ipAddress: string, 
    reason: 'used' | 'logout' | 'security' = 'logout'
  ): Promise<boolean> {
    try {
      const result = await db.query(
        `UPDATE refresh_tokens 
         SET revoked = true, 
             revoked_at = NOW(), 
             revoked_by_ip = $1,
             revoke_reason = $2
         WHERE token = $3`,
        [ipAddress, reason, token]
      );
      
      // Verificar que se actualizó al menos una fila
      return result.rowCount ? result.rowCount > 0 : false;
    } catch (error: unknown) {
      const errorMessage = error instanceof Error ? error.message : 'Error desconocido al revocar token';
      logger.error('Error revoking refresh token', { 
        error: errorMessage,
        token,
        stack: error instanceof Error ? error.stack : undefined
      });
      return false;
    }
  }

  /**
   * Revoca todos los tokens de actualización de un usuario
   */
  static async revokeAllUserTokens(userId: string, ipAddress: string): Promise<boolean> {
    try {
      await db.query(
        `UPDATE refresh_tokens 
         SET revoked = true, 
             revoked_at = NOW(), 
             revoked_by_ip = $1,
             revoke_reason = 'security'
         WHERE user_id = $2 AND revoked = false`,
        [ipAddress, userId]
      );
      return true;
    } catch (error) {
      logger.error('Error revoking all user tokens', { error, userId });
      return false;
    }
  }

  /**
   * Verifica si un token de actualización es válido
   */
  static async verifyToken(token: string): Promise<{ isValid: boolean; reason?: string }> {
    try {
      const refreshToken = await this.getByToken(token);
      
      if (!refreshToken) {
        return { isValid: false, reason: 'Token no encontrado' };
      }
      
      if (refreshToken.revoked) {
        return { isValid: false, reason: 'Token revocado' };
      }
      
      if (new Date(refreshToken.expiresAt) < new Date()) {
        return { isValid: false, reason: 'Token expirado' };
      }
      
      return { isValid: true };
    } catch (error) {
      logger.error('Error verifying refresh token', { error });
      return { isValid: false, reason: 'Error al verificar el token' };
    }
  }

  /**
   * Elimina tokens expirados
   */
  static async removeOldRefreshTokens(days: number = 30): Promise<void> {
    try {
      const cutoffDate = new Date();
      cutoffDate.setDate(cutoffDate.getDate() - days);
      
      await db.query(
        'DELETE FROM refresh_tokens WHERE created_at < $1',
        [cutoffDate]
      );
    } catch (error) {
      logger.error('Error removing old refresh tokens', { error });
    }
  }
}

// Inicialización: eliminar tokens viejos al iniciar el servicio
TokenService.removeOldRefreshTokens().catch(error => {
  logger.error('Error during initial cleanup of old refresh tokens', { error });
});
