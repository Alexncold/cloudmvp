import jwt, { JwtPayload, SignOptions, VerifyOptions, TokenExpiredError, JsonWebTokenError, Algorithm } from 'jsonwebtoken';
import { logger } from './logger';

export type TokenType = 'access' | 'refresh' | 'email-verification' | 'password-reset';

// Extend JwtPayload with our custom fields
export interface TokenPayload extends JwtPayload {
  userId: string;
  email: string;
  type: TokenType;
  iat?: number;
  exp?: number;
  jti?: string; // JWT ID for tracking individual tokens
  ver?: number; // Secret version for key rotation
  // Add index signature to allow dynamic properties
  [key: string]: any;
}

// Interface for JWT secret configuration
interface JwtSecretConfig {
  current: string;
  previous?: string;
  currentVersion: number;
  keyRotationInterval: number; // in milliseconds
  lastRotation: number;
}

// Initialize JWT secret configuration
const JWT_SECRET_CONFIG: JwtSecretConfig = (() => {
  // Validate required environment variables
  if (!process.env.JWT_SECRET) {
    logger.error('JWT_SECRET environment variable is not set');
    process.exit(1);
  }

  // Generate a strong secret if not in production (for development only)
  const currentSecret = process.env.JWT_SECRET;
  
  // Check secret strength in production
  if (process.env.NODE_ENV === 'production' && currentSecret.length < 32) {
    logger.error('JWT_SECRET is too short. It must be at least 32 characters long in production.');
    process.exit(1);
  }

  return {
    current: currentSecret,
    previous: process.env.PREV_JWT_SECRET,
    currentVersion: parseInt(process.env.JWT_SECRET_VERSION || '1', 10),
    keyRotationInterval: 30 * 24 * 60 * 60 * 1000, // 30 days in milliseconds
    lastRotation: Date.now(),
  };
})();

// Validate required JWT configuration
if (!JWT_SECRET_CONFIG.current) {
  logger.error('JWT_SECRET is not defined in environment variables');
  process.exit(1);
}

// Token options with secure defaults
const TOKEN_OPTIONS: Record<TokenType, SignOptions> = {
  'access': {
    expiresIn: '15m',
    algorithm: 'HS256',
  },
  'refresh': {
    expiresIn: '30d',
    algorithm: 'HS256',
  },
  'email-verification': {
    expiresIn: '24h',
    algorithm: 'HS256',
  },
  'password-reset': {
    expiresIn: '1h',
    algorithm: 'HS256',
  },
};

const DEFAULT_VERIFY_OPTIONS: VerifyOptions = {
  algorithms: ['HS256'] as Algorithm[],
  ignoreExpiration: false,
};

// Generate a unique ID for each token
function generateTokenId(): string {
  return Math.random().toString(36).substring(2, 15) + 
         Math.random().toString(36).substring(2, 15);
}

// Get the appropriate secret for a token version
function getSecretForVersion(version: number): string | undefined {
  if (version === JWT_SECRET_CONFIG.currentVersion) {
    return JWT_SECRET_CONFIG.current;
  }
  if (version === JWT_SECRET_CONFIG.currentVersion - 1 && JWT_SECRET_CONFIG.previous) {
    return JWT_SECRET_CONFIG.previous;
  }
  return undefined;
}

// Rotate the JWT secret (to be called periodically)
function rotateJwtSecretInternal(): void {
  const now = Date.now();
  
  // Don't rotate too frequently
  if (now - JWT_SECRET_CONFIG.lastRotation < JWT_SECRET_CONFIG.keyRotationInterval / 2) {
    logger.warn('JWT secret rotation attempted too soon');
    return;
  }
  
  logger.info('Rotating JWT secret...');
  
  // Move current to previous
  JWT_SECRET_CONFIG.previous = JWT_SECRET_CONFIG.current;
  
  // Generate a new secret (in production, this should come from a secure source)
  JWT_SECRET_CONFIG.current = require('crypto').randomBytes(64).toString('hex');
  JWT_SECRET_CONFIG.currentVersion += 1;
  JWT_SECRET_CONFIG.lastRotation = now;
  
  logger.info('JWT secret rotated successfully', { 
    version: JWT_SECRET_CONFIG.currentVersion,
    lastRotation: new Date(JWT_SECRET_CONFIG.lastRotation).toISOString()
  });
}

// Generate a signed JWT token with the given payload and options
export function generateToken(
  payload: Omit<TokenPayload, 'iat' | 'exp' | 'jti' | 'ver'> & { 
    type: TokenType;
    userId: string;
    email: string;
  },
  options: SignOptions = {}
): string {
  // Validate required fields
  if (!payload.userId || !payload.email || !payload.type) {
    throw new Error('Missing required token payload fields');
  }

  const now = Math.floor(Date.now() / 1000);
  const tokenOptions = { ...TOKEN_OPTIONS[payload.type], ...options };
  
  // Create the token payload with all required fields
  const tokenPayload: TokenPayload = {
    userId: payload.userId,
    email: payload.email,
    type: payload.type,
    // Optional fields
    ...(payload.role && { role: payload.role }),
    // System fields
    iat: now,
    jti: generateTokenId(),
    ver: JWT_SECRET_CONFIG.currentVersion,
  };

  try {
    // Sign the token with the current secret
    return jwt.sign(tokenPayload, JWT_SECRET_CONFIG.current, tokenOptions);
  } catch (error) {
    logger.error('Error generating token', { 
      error: error instanceof Error ? error.message : 'Unknown error',
      userId: payload.userId,
      type: payload.type
    });
    throw new Error('Failed to generate token');
  }
}

// Generate an access token
export function generateAccessToken(userId: string, email: string, role?: string): string {
  return generateToken({
    userId,
    email,
    type: 'access',
    ...(role && { role }), // Include role if provided
  });
}

// Generate a refresh token
export function generateRefreshToken(userId: string, email: string): string {
  return generateToken({
    userId,
    email,
    type: 'refresh',
  });
}

// Generate both access and refresh tokens
export function generateTokens(
  userId: string, 
  email: string, 
  role?: string
): { 
  accessToken: string; 
  refreshToken: string;
  accessTokenExpires: number;
  refreshTokenExpires: number;
} {
  if (!userId || !email) {
    throw new Error('User ID and email are required to generate tokens');
  }

  const accessToken = generateAccessToken(userId, email, role);
  const refreshToken = generateRefreshToken(userId, email);
  
  // Calculate token expiration times (in seconds since epoch)
  const now = Math.floor(Date.now() / 1000);
  const accessTokenExpires = now + (15 * 60); // 15 minutes
  const refreshTokenExpires = now + (30 * 24 * 60 * 60); // 30 days
  
  logger.info('Generated new token pair', { 
    userId, 
    accessTokenExpires: new Date(accessTokenExpires * 1000).toISOString(),
    refreshTokenExpires: new Date(refreshTokenExpires * 1000).toISOString()
  });
  
  return { 
    accessToken, 
    refreshToken, 
    accessTokenExpires,
    refreshTokenExpires 
  };
}

// Verify a JWT token with support for key rotation
export function verifyToken(
  token: string, 
  type: TokenType = 'access',
  options: VerifyOptions = {}
): TokenPayload {
  // Validate input parameters
  if (!token || typeof token !== 'string') {
    throw new JsonWebTokenError('Token must be a non-empty string');
  }

  // Normalize token by removing 'Bearer ' prefix if present
  const normalizedToken = token.startsWith('Bearer ') ? token.substring(7) : token;
  
  // Configure verification options
  const verifyOptions: VerifyOptions = { 
    ...DEFAULT_VERIFY_OPTIONS, 
    ...options,
    // Force algorithm to prevent algorithm confusion attacks
    algorithms: ['HS256'] as Algorithm[]
  };
  
  // First, try to decode without verification to get the token version
  let decoded: jwt.Jwt | null = null;
  try {
    decoded = jwt.decode(normalizedToken, { complete: true });
  } catch (decodeError) {
    throw new JsonWebTokenError('Failed to decode token');
  }
  
  if (!decoded || typeof decoded === 'string' || !decoded.payload) {
    throw new JsonWebTokenError('Invalid token format');
  }
  
  // Type assertion for the payload
  const payload = decoded.payload as JwtPayload;
  const tokenVersion = payload.ver || 1;
  
  // Get the appropriate secret based on the token version
  const secret = getSecretForVersion(tokenVersion);
  if (!secret) {
    logger.warn('Invalid token version', { 
      tokenVersion,
      currentVersion: JWT_SECRET_CONFIG.currentVersion 
    });
    throw new JsonWebTokenError('Invalid token');
  }
  
  // Verify the token with the appropriate secret
  let verified: TokenPayload;
  try {
    const decoded = jwt.verify(normalizedToken, secret, verifyOptions) as JwtPayload;
    // Ensure required fields exist
    if (!decoded.userId || !decoded.email || !decoded.type) {
      throw new JsonWebTokenError('Invalid token payload');
    }
    verified = decoded as TokenPayload;
  } catch (error) {
    // Handle specific JWT errors
    if (error instanceof TokenExpiredError) {
      logger.warn('Token expired', { 
        tokenId: payload.jti ? `${payload.jti.substring(0, 8)}...` : 'unknown',
        userId: payload.userId,
        type,
        expiredAt: error.expiredAt
      });
      throw error;
    }
    
    // Generic JWT error
    if (error instanceof JsonWebTokenError) {
      logger.warn('Invalid token', { 
        error: error.message,
        tokenId: payload.jti ? `${payload.jti.substring(0, 8)}...` : 'unknown',
        type
      });
      // Don't leak too much information in the error message
      throw new JsonWebTokenError('Invalid token');
    }
    
    // Unknown error
    logger.error('Unexpected error during token verification', { 
      error: error instanceof Error ? error.message : 'Unknown error',
      stack: error instanceof Error ? error.stack : undefined,
      type
    });
    throw new JsonWebTokenError('Token verification failed');
  }
  
  // Additional token validation
  try {
    // Verify token type
    if (verified.type !== type) {
      logger.warn('Token type mismatch', { 
        expected: type, 
        actual: verified.type,
        tokenId: verified.jti ? `${verified.jti.substring(0, 8)}...` : 'unknown',
        userId: verified.userId
      });
      throw new JsonWebTokenError('Invalid token type');
    }
    
    // Check if token was issued in the future (clock skew tolerance: 5 minutes)
    const now = Math.floor(Date.now() / 1000);
    if (verified.iat && verified.iat > now + 300) {
      logger.warn('Token issued in the future', { 
        issuedAt: new Date(verified.iat * 1000).toISOString(),
        currentTime: new Date().toISOString(),
        tokenId: verified.jti ? `${verified.jti.substring(0, 8)}...` : 'unknown',
        userId: verified.userId
      });
      throw new JsonWebTokenError('Invalid token');
    }
    
    // If we're using an old secret, we should issue a new token with the current secret
    if (tokenVersion < JWT_SECRET_CONFIG.currentVersion) {
      logger.info('Issuing new token with current secret version', { 
        tokenVersion,
        currentVersion: JWT_SECRET_CONFIG.currentVersion,
        tokenId: verified.jti ? `${verified.jti.substring(0, 8)}...` : 'unknown',
        userId: verified.userId
      });
      // The client should detect this and update their token
      verified.needsRefresh = true;
    }
    
    return verified;
  } catch (error) {
    // Re-throw any validation errors
    if (error instanceof JsonWebTokenError) {
      throw error;
    }
    
    // Log and re-throw unexpected errors
    logger.error('Unexpected error during token validation', { 
      error: error instanceof Error ? error.message : 'Unknown error',
      stack: error instanceof Error ? error.stack : undefined,
      tokenId: verified?.jti ? `${verified.jti.substring(0, 8)}...` : 'unknown',
      userId: verified?.userId
    });
    
    throw new JsonWebTokenError('Token validation failed');
  }
}

/**
 * Get the expiration date of a token
 */
export function getTokenExpiration(token: string): Date | null {
  try {
    const decoded = jwt.decode(token, { complete: true });
    if (!decoded || typeof decoded === 'string' || !decoded.payload) {
      return null;
    }
    
    const payload = decoded.payload as TokenPayload;
    if (!payload.exp) return null;
    
    return new Date(payload.exp * 1000);
  } catch (error) {
    logger.error('Error decoding token expiration', { 
      error: error instanceof Error ? error.message : 'Unknown error' 
    });
    return null;
  }
}

/**
 * Decode a token without verification (client-side only)
 */
export function decodeToken<T = TokenPayload>(token: string): T | null {
  try {
    const decoded = jwt.decode(token, { complete: true });
    if (!decoded || typeof decoded === 'string') {
      return null;
    }
    return decoded.payload as T;
  } catch (error) {
    return null;
  }
}

// Re-export JWT error types for consistent error handling
export { TokenExpiredError, JsonWebTokenError } from 'jsonwebtoken';

/**
 * Check if an error is a JWT error
 */
export function isJwtError(error: unknown): error is JsonWebTokenError | TokenExpiredError {
  return error instanceof JsonWebTokenError || error instanceof TokenExpiredError;
}

// Export the secret rotation function
export const rotateJwtSecret = rotateJwtSecretInternal;

/**
 * Get the current JWT secret configuration (for administrative purposes)
 */
export function getJwtSecretInfo() {
  return {
    currentVersion: JWT_SECRET_CONFIG.currentVersion,
    lastRotation: new Date(JWT_SECRET_CONFIG.lastRotation).toISOString(),
    nextRotation: new Date(JWT_SECRET_CONFIG.lastRotation + JWT_SECRET_CONFIG.keyRotationInterval).toISOString(),
  };
}

/**
 * Middleware to check if a token needs to be refreshed
 */
export function needsTokenRefresh(payload: TokenPayload): boolean {
  // If the token is from a previous secret version, it needs to be refreshed
  if (payload.ver && payload.ver < JWT_SECRET_CONFIG.currentVersion) {
    return true;
  }
  
  // If the token is close to expiring, it should be refreshed
  if (payload.exp) {
    const now = Math.floor(Date.now() / 1000);
    const timeUntilExpiry = payload.exp - now;
    const tokenType = payload.type || 'access';
    
    // Refresh tokens should be refreshed when they have 7 days or less remaining
    if (tokenType === 'refresh' && timeUntilExpiry <= 7 * 24 * 60 * 60) {
      return true;
    }
    
    // Access tokens should be refreshed when they have 5 minutes or less remaining
    if (tokenType === 'access' && timeUntilExpiry <= 5 * 60) {
      return true;
    }
  }
  
  return false;
}
