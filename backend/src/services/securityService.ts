import { db } from './db';
import { logger } from '../utils/logger';

export class SecurityService {
  private static readonly MAX_FAILED_ATTEMPTS = 5;
  private static readonly LOCKOUT_DURATION_MS = 15 * 60 * 1000; // 15 minutos
  private static readonly CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutos

  // Cache simple en memoria para evitar consultas frecuentes a la base de datos
  private static failedAttemptsCache: Map<string, { count: number; lastAttempt: number }> = new Map();
  private static lastCleanup = Date.now();

  /**
   * Registra un intento fallido de inicio de sesión
   */
  static async recordFailedLoginAttempt(identifier: string, ip: string): Promise<void> {
    try {
      // Limpiar caché si es necesario
      this.cleanupCacheIfNeeded();

      // Actualizar caché
      const cacheKey = `${identifier}:${ip}`;
      const cached = this.failedAttemptsCache.get(cacheKey) || { count: 0, lastAttempt: 0 };
      
      this.failedAttemptsCache.set(cacheKey, {
        count: cached.count + 1,
        lastAttempt: Date.now()
      });

      // Registrar en la base de datos (sin bloquear la respuesta)
      this.logFailedAttempt(identifier, ip).catch(error => {
        logger.error('Error logging failed login attempt', { error, identifier, ip });
      });
    } catch (error) {
      logger.error('Error recording failed login attempt', { error, identifier, ip });
    }
  }

  /**
   * Verifica si una dirección IP o identificador está bloqueado
   */
  static isBlocked(identifier: string, ip: string): { blocked: boolean; remainingTime?: number } {
    this.cleanupCacheIfNeeded();
    
    const cacheKey = `${identifier}:${ip}`;
    const cached = this.failedAttemptsCache.get(cacheKey);
    
    if (!cached || cached.count < this.MAX_FAILED_ATTEMPTS) {
      return { blocked: false };
    }
    
    const timeSinceLastAttempt = Date.now() - cached.lastAttempt;
    if (timeSinceLastAttempt > this.LOCKOUT_DURATION_MS) {
      // El período de bloqueo ha terminado
      this.failedAttemptsCache.delete(cacheKey);
      return { blocked: false };
    }
    
    // Aún en período de bloqueo
    return { 
      blocked: true, 
      remainingTime: Math.ceil((this.LOCKOUT_DURATION_MS - timeSinceLastAttempt) / 1000) // en segundos
    };
  }

  /**
   * Restablece el contador de intentos fallidos
   */
  static resetFailedAttempts(identifier: string, ip: string): void {
    const cacheKey = `${identifier}:${ip}`;
    this.failedAttemptsCache.delete(cacheKey);
    
    // También limpiar de la base de datos (sin bloquear)
    this.clearFailedAttempts(identifier, ip).catch(error => {
      logger.error('Error clearing failed login attempts', { error, identifier, ip });
    });
  }

  /**
   * Limpia la caché si ha pasado el tiempo definido
   */
  private static cleanupCacheIfNeeded(): void {
    const now = Date.now();
    if (now - this.lastCleanup < this.CACHE_TTL_MS) return;

    for (const [key, value] of this.failedAttemptsCache.entries()) {
      if (now - value.lastAttempt > this.LOCKOUT_DURATION_MS) {
        this.failedAttemptsCache.delete(key);
      }
    }
    
    this.lastCleanup = now;
  }

  /**
   * Registra un intento fallido en la base de datos
   */
  private static async logFailedAttempt(identifier: string, ip: string): Promise<void> {
    await db.query(
      `INSERT INTO failed_login_attempts (identifier, ip_address, attempted_at)
       VALUES ($1, $2, NOW())
       ON CONFLICT (identifier, ip_address) 
       DO UPDATE SET 
         attempt_count = failed_login_attempts.attempt_count + 1,
         attempted_at = NOW()
       RETURNING *`,
      [identifier, ip]
    );
  }

  /**
   * Limpia los intentos fallidos de la base de datos
   */
  private static async clearFailedAttempts(identifier: string, ip: string): Promise<void> {
    await db.query(
      'DELETE FROM failed_login_attempts WHERE identifier = $1 AND ip_address = $2',
      [identifier, ip]
    );
  }

  /**
   * Obtiene el número de intentos fallidos recientes
   */
  static async getFailedAttempts(identifier: string, ip: string): Promise<number> {
    try {
      const result = await db.query(
        `SELECT attempt_count 
         FROM failed_login_attempts 
         WHERE identifier = $1 AND ip_address = $2 
         AND attempted_at > NOW() - INTERVAL '15 minutes'`,
        [identifier, ip]
      );
      
      return result.rows[0]?.attempt_count || 0;
    } catch (error) {
      logger.error('Error getting failed login attempts', { error, identifier, ip });
      return 0;
    }
  }
}
