import jwt, { JwtPayload, SignOptions, VerifyOptions, TokenExpiredError, JsonWebTokenError } from 'jsonwebtoken';
import { logger } from './logger';

export type TokenType = 'access' | 'refresh' | 'email-verification' | 'password-reset';

export interface TokenPayload extends JwtPayload {
  userId: string;
  email: string;
  type: TokenType;
  iat?: number;
  exp?: number;
}

const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET) {
  logger.error('JWT_SECRET is not defined in environment variables');
  process.exit(1);
}

const ACCESS_TOKEN_OPTIONS: SignOptions = {
  expiresIn: '15m',
  algorithm: 'HS256', // Asegura que se use un algoritmo seguro
};

const REFRESH_TOKEN_OPTIONS: SignOptions = {
  expiresIn: '30d',
  algorithm: 'HS256',
};

const VERIFY_OPTIONS: VerifyOptions = {
  algorithms: ['HS256'],
  ignoreExpiration: false,
};

export function generateAccessToken(userId: string, email: string): string {
  const payload: TokenPayload = {
    userId,
    email,
    type: 'access', // Indica que es un token de acceso
    iat: Math.floor(Date.now() / 1000), // Fecha de emisión
  };

  return jwt.sign(payload, JWT_SECRET!, ACCESS_TOKEN_OPTIONS);
}

export function generateRefreshToken(userId: string, email: string): string {
  const payload: TokenPayload = {
    userId,
    email,
    type: 'refresh', // Indica que es un token de refresco
    iat: Math.floor(Date.now() / 1000),
  };

  return jwt.sign(payload, JWT_SECRET!, REFRESH_TOKEN_OPTIONS);
}

export function generateTokens(userId: string, email: string): { accessToken: string; refreshToken: string } {
  return {
    accessToken: generateAccessToken(userId, email),
    refreshToken: generateRefreshToken(userId, email),
  };
}

export function verifyToken(token: string, type: 'access' | 'refresh' = 'access'): TokenPayload {
  try {
    const decoded = jwt.verify(token, JWT_SECRET!, VERIFY_OPTIONS) as TokenPayload;
    
    // Verificar que el tipo de token coincida
    if (decoded.type !== type) {
      throw new Error(`Invalid token type: expected ${type} but got ${decoded.type}`);
    }
    
    return decoded;
  } catch (error) {
    logger.error('Token verification failed:', { 
      error: error instanceof Error ? error.message : 'Unknown error',
      token: token.substring(0, 10) + '...' // Log solo una parte del token por seguridad
    });
    throw error;
  }
}

export function getTokenExpiration(token: string): Date | null {
  try {
    const decoded = jwt.decode(token) as { exp?: number };
    if (!decoded?.exp) return null;
    return new Date(decoded.exp * 1000);
  } catch (error) {
    return null;
  }
}

// Función para decodificar el token sin verificación (solo para uso en el cliente)
export function decodeToken<T = TokenPayload>(token: string): T | null {
  try {
    return jwt.decode(token) as T;
  } catch (error) {
    return null;
  }
}

// Re-export JWT error types for consistent error handling
export { TokenExpiredError, JsonWebTokenError } from 'jsonwebtoken';

// Helper to check if an error is a JWT error
export function isJwtError(error: unknown): error is JsonWebTokenError | TokenExpiredError {
  return error instanceof JsonWebTokenError || error instanceof TokenExpiredError;
}

// Helper to generate token with custom type and expiration
export function generateToken(
  payload: Omit<TokenPayload, 'iat' | 'exp'>,
  expiresIn: string
): string {
  // Calculate expiration time
  const now = Math.floor(Date.now() / 1000);
  const exp = now + (typeof expiresIn === 'string' 
    ? (parseInt(expiresIn) || 0) 
    : (expiresIn || 0));
  
  // Create token with explicit type casting
  return jwt.sign(
    { ...payload, iat: now, exp } as TokenPayload,
    JWT_SECRET!,
    { algorithm: 'HS256' }
  );
}
