import { Request, Response } from 'express';
import { PoolClient } from 'pg';
import { DatabaseService } from '../services/db';
import bcrypt from 'bcryptjs';
import { validationResult } from 'express-validator';
import jwt, { JwtPayload, TokenExpiredError, JsonWebTokenError, SignOptions } from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';
import emailService from '../services/emailService';
import { logger } from '../utils/logger';

// Token expiration times (in seconds)
const TOKEN_EXPIRATION = {
  ACCESS: 15 * 60, // 15 minutes
  REFRESH: 30 * 24 * 60 * 60, // 30 days
  EMAIL_VERIFICATION: 24 * 60 * 60, // 1 day
  PASSWORD_RESET: 1 * 60 * 60, // 1 hour
} as const;

// Database user interfaces
export interface BaseUser {
  id: string;
  email: string;
  is_verified: boolean;
  created_at: Date;
  updated_at: Date;
}

export interface LocalUser extends BaseUser {
  name: string;
  password_hash: string;
  google_id?: string | null;
  google_refresh_token?: string | null;
  verification_token?: string | null;
  verification_token_expires?: Date | null;
  password_reset_token?: string | null;
  password_reset_expires?: Date | null;
  refresh_token?: string | null;
}

declare global {
  namespace Express {
    interface User extends BaseUser {}
    interface Request {
      user?: User;
    }
  }
}

// Extend JwtPayload to include custom properties
export type TokenType = 'access' | 'refresh' | 'email-verification' | 'password-reset';

export interface CustomJwtPayload extends JwtPayload {
  userId: string;
  email: string;
  type: TokenType;
}

// Create a factory function that accepts a database service
export const createAuthController = (dbService: DatabaseService = new DatabaseService()) => {
  // Helper function to handle database operations with a client
  const withClient = async <T>(callback: (client: PoolClient) => Promise<T>): Promise<T> => {
    const client = await dbService.getClient();
    try {
      return await callback(client);
    } finally {
      client.release();
    }
  };

  // Token generation helper function
  const generateToken = (payload: Omit<CustomJwtPayload, 'exp' | 'iat'>, expiresIn: string | number): string => {
    if (!process.env.JWT_SECRET) {
      throw new Error('JWT_SECRET is not defined');
    }
    return jwt.sign(
      payload,
      process.env.JWT_SECRET,
      { expiresIn } as SignOptions
    );
  };

  const generateAuthTokens = (userId: string, email: string) => {
    const accessToken = generateToken(
      { userId, email, type: 'access' as const },
      TOKEN_EXPIRATION.ACCESS
    );
    
    const refreshToken = generateToken(
      { userId, email, type: 'refresh' as const },
      TOKEN_EXPIRATION.REFRESH
    );
    
    return { accessToken, refreshToken };
  };

  // Register a new user
  const register = async (req: Request, res: Response) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { email, password, name } = req.body;

    try {
      // Check if user already exists
      const userExists = await withClient(async (client) => {
        const result = await client.query('SELECT id FROM users WHERE email = $1', [email]);
        return result.rows.length > 0;
      });

      if (userExists) {
        return res.status(400).json({ error: 'User already exists' });
      }

      // Hash password
      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(password, salt);

      // Generate verification token
      const verificationToken = generateToken(
        { userId: uuidv4(), email, type: 'email-verification' as const },
        TOKEN_EXPIRATION.EMAIL_VERIFICATION
      );

      // Create user in database
      const newUser = await withClient(async (client) => {
        const result = await client.query<LocalUser>(
          `INSERT INTO users (email, name, password_hash, verification_token, verification_token_expires)
           VALUES ($1, $2, $3, $4, NOW() + INTERVAL '24 hours')
           RETURNING id, email, is_verified, created_at, updated_at`,
          [email, name, hashedPassword, verificationToken]
        );
        return result.rows[0];
      });

      // Generate tokens
      const { accessToken, refreshToken } = generateAuthTokens(newUser.id, newUser.email);

      // Set refresh token as HTTP-only cookie
      res.cookie('refreshToken', refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: TOKEN_EXPIRATION.REFRESH * 1000, // in milliseconds
      });

      // In a real application, you would send an actual verification email here
      console.log(`Verification email sent to ${email} with token: ${verificationToken}`);

      // Return user data and access token
      return res.status(201).json({
        user: {
          id: newUser.id,
          email: newUser.email,
          is_verified: newUser.is_verified,
          created_at: newUser.created_at,
          updated_at: newUser.updated_at,
        },
        accessToken,
      });
    } catch (error) {
      console.error('Registration error:', error);
      return res.status(500).json({ error: 'Internal server error' });
    }
  };

  // Login with email and password
  const login = async (req: Request, res: Response) => {
    console.log('Login request received:', { body: req.body });
    
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      console.log('Validation errors:', errors.array());
      return res.status(400).json({ errors: errors.array() });
    }

    const { email, password } = req.body;
    console.log('Processing login for email:', email);

    try {
      // Find user by email
      console.log('Searching for user in database...');
      const user = await withClient(async (client) => {
        const result = await client.query<LocalUser>(
          'SELECT * FROM users WHERE email = $1',
          [email]
        );
        console.log('Database query result:', { 
          rowCount: result.rowCount,
          user: result.rows[0] ? { 
            id: result.rows[0].id, 
            email: result.rows[0].email,
            is_verified: result.rows[0].is_verified 
          } : null 
        });
        return result.rows[0];
      });

      // Check if user exists
      if (!user) {
        console.log('User not found for email:', email);
        return res.status(401).json({ error: 'Invalid email or password' });
      }

      console.log('User found:', { 
        id: user.id, 
        email: user.email, 
        is_verified: user.is_verified 
      });

      // Check if user is verified
      if (!user.is_verified) {
        console.log('User email not verified:', user.email);
        return res.status(403).json({ 
          error: 'Please verify your email before logging in' 
        });
      }

      console.log('Verifying password...');
      // Check password
      const isMatch = await bcrypt.compare(password, user.password_hash);
      console.log('Password verification result:', { isMatch });
      
      if (!isMatch) {
        console.log('Invalid password for user:', user.email);
        return res.status(401).json({ error: 'Invalid email or password' });
      }

      // Generate tokens
      const { accessToken, refreshToken } = generateAuthTokens(user.id, user.email);

      // Update refresh token in database
      await withClient(async (client) => {
        await client.query(
          'UPDATE users SET refresh_token = $1, updated_at = NOW() WHERE id = $2',
          [refreshToken, user.id]
        );
      });

      // Set refresh token as HTTP-only cookie
      res.cookie('refreshToken', refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: TOKEN_EXPIRATION.REFRESH * 1000, // in milliseconds
      });

      // Return user data and access token
      return res.status(200).json({
        user: {
          id: user.id,
          email: user.email,
          name: user.name,
          is_verified: user.is_verified,
          created_at: user.created_at,
          updated_at: user.updated_at,
        },
        accessToken,
      });
    } catch (error) {
      console.error('Login error:', error);
      return res.status(500).json({ error: 'Internal server error' });
    }
  };

  // Verify user email with token
  const verifyEmail = async (req: Request, res: Response) => {
    const { token } = req.params;

    if (!token) {
      return res.status(400).json({ error: 'Verification token is required' });
    }

    try {
      // Verify the token
      const payload = jwt.verify(token, process.env.JWT_SECRET!) as CustomJwtPayload;
      
      if (payload.type !== 'email-verification') {
        return res.status(400).json({ error: 'Invalid token type' });
      }

      // Find user by email from token
      const user = await withClient(async (client) => {
        const result = await client.query<LocalUser>(
          'SELECT * FROM users WHERE email = $1',
          [payload.email]
        );
        return result.rows[0];
      });

      if (!user) {
        return res.status(404).json({ error: 'User not found' });
      }

      // Check if already verified
      if (user.is_verified) {
        return res.status(400).json({ error: 'Email already verified' });
      }

      // Check if token matches and is not expired
      if (user.verification_token !== token) {
        return res.status(400).json({ error: 'Invalid verification token' });
      }

      if (user.verification_token_expires && new Date() > user.verification_token_expires) {
        return res.status(400).json({ error: 'Verification token has expired' });
      }

      // Update user as verified
      await withClient(async (client) => {
        await client.query(
          `UPDATE users 
           SET is_verified = true, 
               verification_token = NULL, 
               verification_token_expires = NULL,
               updated_at = NOW()
           WHERE id = $1`,
          [user.id]
        );
      });

      return res.status(200).json({ message: 'Email verified successfully' });
    } catch (error) {
      if (error instanceof TokenExpiredError) {
        return res.status(400).json({ error: 'Verification token has expired' });
      } else if (error instanceof JsonWebTokenError) {
        return res.status(400).json({ error: 'Invalid verification token' });
      }
      
      console.error('Email verification error:', error);
      return res.status(500).json({ error: 'Internal server error' });
    }
  };

  // Refresh access token using refresh token
  const refreshToken = async (req: Request, res: Response) => {
    const { refreshToken } = req.cookies;

    if (!refreshToken) {
      return res.status(401).json({ error: 'Refresh token is required' });
    }

    try {
      // Verify the refresh token
      const payload = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET || process.env.JWT_SECRET!) as CustomJwtPayload;
      
      if (payload.type !== 'refresh') {
        return res.status(400).json({ error: 'Invalid token type' });
      }

      // Find user by ID from token
      const user = await withClient(async (client) => {
        const result = await client.query<LocalUser>(
          'SELECT * FROM users WHERE id = $1 AND refresh_token = $2',
          [payload.userId, refreshToken]
        );
        return result.rows[0];
      });

      if (!user) {
        return res.status(401).json({ error: 'Invalid refresh token' });
      }

      // Generate new tokens
      const { accessToken: newAccessToken, refreshToken: newRefreshToken } = generateAuthTokens(user.id, user.email);

      // Update refresh token in database
      await withClient(async (client) => {
        await client.query(
          'UPDATE users SET refresh_token = $1, updated_at = NOW() WHERE id = $2',
          [newRefreshToken, user.id]
        );
      });

      // Set new refresh token as HTTP-only cookie
      res.cookie('refreshToken', newRefreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: TOKEN_EXPIRATION.REFRESH * 1000, // in milliseconds
      });

      // Return new access token
      return res.status(200).json({
        accessToken: newAccessToken,
        user: {
          id: user.id,
          email: user.email,
          name: user.name,
          is_verified: user.is_verified,
        },
      });
    } catch (error) {
      if (error instanceof TokenExpiredError) {
        return res.status(401).json({ error: 'Refresh token has expired' });
      } else if (error instanceof JsonWebTokenError) {
        return res.status(401).json({ error: 'Invalid refresh token' });
      }
      
      console.error('Token refresh error:', error);
      return res.status(500).json({ error: 'Internal server error' });
    }
  };

  // Logout user by clearing refresh token
  const logout = async (req: Request, res: Response) => {
    const { refreshToken } = req.cookies;

    if (!refreshToken) {
      return res.status(200).json({ message: 'Logged out successfully' });
    }

    try {
      // Verify the refresh token to get user ID
      const payload = jwt.verify(
        refreshToken, 
        process.env.REFRESH_TOKEN_SECRET || process.env.JWT_SECRET!
      ) as CustomJwtPayload;

      // Clear the refresh token from the database
      await withClient(async (client) => {
        await client.query(
          'UPDATE users SET refresh_token = NULL, updated_at = NOW() WHERE id = $1',
          [payload.userId]
        );
      });
    } catch (error) {
      // If token is invalid, still clear the cookie
      console.error('Error during logout:', error);
    }

    // Clear the refresh token cookie
    res.clearCookie('refreshToken', {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
    });

    return res.status(200).json({ message: 'Logged out successfully' });
  };

  // Get current authenticated user
  const getCurrentUser = (req: Request, res: Response) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Not authenticated' });
    }

    // Return user data without sensitive information
    const { id, email, name, is_verified, created_at, updated_at } = req.user;
    return res.status(200).json({
      user: {
        id,
        email,
        name,
        is_verified,
        created_at,
        updated_at,
      },
    });
  };

  // Return the controller methods with the injected dbService
  // Forgot password handler
  const forgotPassword = async (req: Request, res: Response) => {
    const { email } = req.body;
    
    try {
      // Buscar usuario por email
      const user = await withClient(async (client) => {
        const result = await client.query<LocalUser>(
          'SELECT id, email, name FROM users WHERE email = $1',
          [email]
        );
        return result.rows[0] || null;
      });

      // Si el usuario no existe, no revelar esta información por seguridad
      if (!user) {
        return res.status(200).json({ 
          message: 'Si existe una cuenta con este correo, se ha enviado un enlace para restablecer la contraseña' 
        });
      }

      // Generar token de restablecimiento
      const resetToken = generateToken(
        { 
          userId: user.id, 
          email: user.email, 
          type: 'password-reset' as const 
        },
        TOKEN_EXPIRATION.PASSWORD_RESET.toString()
      );

      // Guardar token en la base de datos
      await withClient(async (client) => {
        await client.query(
          `UPDATE users 
           SET password_reset_token = $1, 
               password_reset_expires = NOW() + INTERVAL '1 hour',
               updated_at = NOW()
           WHERE id = $2`,
          [resetToken, user.id]
        );
      });

      // Enviar correo electrónico
      try {
        await emailService.sendPasswordResetEmail(
          user.email,
          user.name || 'Usuario',
          `${process.env.FRONTEND_URL}/reset-password?token=${resetToken}`
        );
      } catch (emailError) {
        logger.error('Error enviando correo de restablecimiento:', emailError);
        // No fallar la petición si falla el envío del correo
      }

      res.status(200).json({ 
        message: 'Si existe una cuenta con este correo, se ha enviado un enlace para restablecer la contraseña' 
      });
    } catch (error) {
      logger.error('Error en forgot-password:', error);
      res.status(500).json({ error: 'Error al procesar la solicitud' });
    }
  };

  // Reset password handler
  const resetPassword = async (req: Request, res: Response) => {
    const { token, password } = req.body;
    
    try {
      // Verificar token
      if (!process.env.JWT_SECRET) {
        throw new Error('JWT_SECRET is not defined');
      }
      
      const decoded = jwt.verify(token, process.env.JWT_SECRET) as CustomJwtPayload;
      
      if (decoded.type !== 'password-reset') {
        return res.status(400).json({ error: 'Token inválido' });
      }

      // Verificar si el token sigue siendo válido en la base de datos
      const user = await withClient(async (client) => {
        const result = await client.query<LocalUser>(
          'SELECT id, email, password_reset_token, password_reset_expires FROM users WHERE id = $1',
          [decoded.userId]
        );
        return result.rows[0] || null;
      });

      if (!user || user.password_reset_token !== token || !user.password_reset_expires) {
        return res.status(400).json({ error: 'Token inválido o expirado' });
      }

      if (new Date() > user.password_reset_expires) {
        return res.status(400).json({ error: 'El enlace de restablecimiento ha expirado' });
      }

      // Hashear nueva contraseña
      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(password, salt);

      // Actualizar contraseña y limpiar token
      await withClient(async (client) => {
        await client.query(
          `UPDATE users 
           SET password_hash = $1, 
               password_reset_token = NULL, 
               password_reset_expires = NULL,
               updated_at = NOW()
           WHERE id = $2`,
          [hashedPassword, user.id]
        );
      });

      res.status(200).json({ message: 'Contraseña actualizada correctamente' });
    } catch (error) {
      if (error instanceof jwt.TokenExpiredError) {
        return res.status(400).json({ error: 'El enlace de restablecimiento ha expirado' });
      }
      if (error instanceof jwt.JsonWebTokenError) {
        return res.status(400).json({ error: 'Token inválido' });
      }
      
      logger.error('Error en reset-password:', error);
      res.status(500).json({ error: 'Error al restablecer la contraseña' });
    }
  };

  return {
    register,
    login,
    verifyEmail,
    refreshToken,
    logout,
    getCurrentUser,
    forgotPassword,
    resetPassword,
  };
};

export default createAuthController;
