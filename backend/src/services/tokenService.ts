import { db } from './db';
import { v4 as uuidv4 } from 'uuid';
import { logger } from '../utils/logger';

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
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + this.REFRESH_TOKEN_LIFETIME_DAYS);

    try {
      const result = await db.query(
        `INSERT INTO refresh_tokens (
          id, user_id, token, expires_at, created_by_ip, user_agent
        ) VALUES ($1, $2, $3, $4, $5, $6)
        RETURNING *`,
        [tokenId, userId, uuidv4(), expiresAt, ipAddress, userAgent]
      );

      return result.rows[0];
    } catch (error) {
      logger.error('Error creating refresh token', { error, userId });
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
      return result.rows[0] || null;
    } catch (error) {
      logger.error('Error getting refresh token', { error });
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
      await db.query(
        `UPDATE refresh_tokens 
         SET revoked = true, 
             revoked_at = NOW(), 
             revoked_by_ip = $1,
             revoke_reason = $2
         WHERE token = $3`,
        [ipAddress, reason, token]
      );
      return true;
    } catch (error) {
      logger.error('Error revoking refresh token', { error, token });
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
