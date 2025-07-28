import { logger } from '../utils/logger';

/**
 * Service for managing blacklisted JWT tokens
 * 
 * This service provides functionality to:
 * - Add tokens to the blacklist
 * - Check if a token is blacklisted
 * - Clean up expired tokens automatically
 * 
 * In a production environment, consider using Redis or a database for distributed blacklisting
 */
export class TokenBlacklist {
  // In-memory store for blacklisted tokens with their expiry timestamps
  private static blacklistedTokens = new Map<string, number>();
  
  // Cleanup interval (1 hour)
  private static cleanupInterval: NodeJS.Timeout;
  
  /**
   * Initialize the cleanup process
   */
  public static initialize(): void {
    // Run cleanup every hour
    this.cleanupInterval = setInterval(() => {
      this.cleanup();
    }, 60 * 60 * 1000); // 1 hour
    
    // Ensure cleanup runs on process exit
    process.on('exit', () => this.shutdown());
    process.on('SIGINT', () => this.shutdown());
    process.on('SIGTERM', () => this.shutdown());
  }
  
  /**
   * Add a token to the blacklist
   * @param token The JWT token to blacklist
   * @param expiryTime Optional expiry time in milliseconds since epoch
   */
  public static add(token: string, expiryTime?: number): void {
    try {
      // If no expiry time provided, try to decode the token to get expiry
      let expiry = expiryTime;
      
      if (!expiry) {
        try {
          // Try to decode the token to get expiry
          const payload = JSON.parse(Buffer.from(token.split('.')[1], 'base64').toString());
          if (payload.exp) {
            // Convert seconds to milliseconds
            expiry = payload.exp * 1000;
          }
        } catch (e) {
          // If we can't decode, use default 24h
          expiry = Date.now() + (24 * 60 * 60 * 1000);
        }
      }
      
      // Default to 24h if still no expiry
      if (!expiry) {
        expiry = Date.now() + (24 * 60 * 60 * 1000);
      }
      
      this.blacklistedTokens.set(token, expiry);
      
      logger.debug('Token added to blacklist', { 
        token: token.substring(0, 10) + '...',
        expiresAt: new Date(expiry).toISOString()
      });
      
    } catch (error) {
      logger.error('Failed to add token to blacklist', { 
        error: error.message,
        stack: error.stack
      });
    }
  }
  
  /**
   * Check if a token is blacklisted
   * @param token The JWT token to check
   * @returns boolean True if the token is blacklisted, false otherwise
   */
  public static isBlacklisted(token: string): boolean {
    try {
      const expiry = this.blacklistedTokens.get(token);
      
      // Token not in blacklist
      if (expiry === undefined) {
        return false;
      }
      
      // Token expired, remove from blacklist
      if (Date.now() > expiry) {
        this.blacklistedTokens.delete(token);
        return false;
      }
      
      // Token is blacklisted and not expired
      return true;
      
    } catch (error) {
      logger.error('Failed to check token blacklist status', {
        token: token ? token.substring(0, 10) + '...' : 'undefined',
        error: error.message,
        stack: error.stack
      });
      
      // In case of error, assume token is not blacklisted
      return false;
    }
  }
  
  /**
   * Remove expired tokens from the blacklist
   */
  private static cleanup(): void {
    try {
      const now = Date.now();
      let removedCount = 0;
      
      for (const [token, expiry] of this.blacklistedTokens.entries()) {
        if (now > expiry) {
          this.blacklistedTokens.delete(token);
          removedCount++;
        }
      }
      
      if (removedCount > 0) {
        logger.debug('Cleaned up expired blacklisted tokens', { 
          count: removedCount,
          remaining: this.blacklistedTokens.size
        });
      }
      
    } catch (error) {
      logger.error('Failed to clean up token blacklist', {
        error: error.message,
        stack: error.stack
      });
    }
  }
  
  /**
   * Get the number of blacklisted tokens
   * @returns Number of currently blacklisted tokens
   */
  public static size(): number {
    return this.blacklistedTokens.size;
  }
  
  /**
   * Clear all tokens from the blacklist
   */
  public static clear(): void {
    const count = this.blacklistedTokens.size;
    this.blacklistedTokens.clear();
    logger.info('Cleared all tokens from blacklist', { count });
  }
  
  /**
   * Clean up resources on shutdown
   */
  private static shutdown(): void {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
    }
    
    // Perform final cleanup
    this.cleanup();
    
    logger.info('TokenBlacklist service shutdown complete', {
      remainingTokens: this.blacklistedTokens.size
    });
  }
}

// Initialize the cleanup process when the module is loaded
TokenBlacklist.initialize();

export default TokenBlacklist;
