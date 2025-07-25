import { Request, Response, NextFunction } from 'express';
import bcrypt from 'bcryptjs';
import { validationResult } from 'express-validator';
import { v4 as uuidv4 } from 'uuid';
import crypto from 'crypto';
import jwt, { JwtPayload } from 'jsonwebtoken';
import { logger } from '../utils/logger';
import { db } from '../services/database';
import { 
  generateAccessToken, 
  generateRefreshToken,
  verifyToken,
  TokenPayload,
  TokenExpiredError,
  JsonWebTokenError
} from '../utils/jwt';
import { sendVerificationEmail, sendPasswordResetEmail } from '../services/emailService';
import { 
  TokenPair, 
  LocalUser, 
  AuthResponse, 
  RegisterRequest, 
  LoginRequest,
  RefreshTokenRequest,
  ForgotPasswordRequest,
  ResetPasswordRequest,
  VerifyEmailRequest,
  ChangePasswordRequest,
  UpdateProfileRequest,
  AuthTokens,
  AuthProviderProfile,
  SessionInfo
} from '../types/auth';

// Extend JwtPayload with our custom token payload
export interface CustomJwtPayload extends JwtPayload, TokenPayload {}

// Extend Express Request type
declare global {
  namespace Express {
    interface Request {
      user?: LocalUser;
    }
  }
}

// Token expiration times (in seconds)
const TOKEN_EXPIRATION = {
  ACCESS: 60 * 15, // 15 minutes
  REFRESH: 60 * 60 * 24 * 7, // 7 days
  EMAIL_VERIFICATION: 60 * 60 * 24, // 24 hours
  PASSWORD_RESET: 60 * 60 * 2, // 2 hours
} as const;

// Token cookie names
const COOKIE_NAMES = {
  ACCESS_TOKEN: 'access_token',
  REFRESH_TOKEN: 'refresh_token',
  AUTHENTICATED: 'authenticated',
} as const;

// User type from our types file
type User = LocalUser;

declare global {
  namespace Express {
    // Extend Express User type to match our LocalUser
    interface User extends LocalUser {}
    interface Request {
      user?: User;
    }
  }
}

// Create a factory function for the auth controller
export const createAuthController = () => {
  // Helper function to hash tokens before storing them
  const hashToken = (token: string): string => {
    return crypto.createHash('sha256').update(token).digest('hex');
  };

  // Helper to set HTTP-only cookies for tokens
  const setTokenCookies = (res: Response, { accessToken, refreshToken }: { accessToken: string; refreshToken: string }) => {
    // Set access token in cookie
    res.cookie('accessToken', accessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict', // CSRF protection
      maxAge: TOKEN_EXPIRATION.ACCESS * 1000, // 15 minutes
    });

    // Set refresh token in HTTP-only cookie
    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: TOKEN_EXPIRATION.REFRESH * 1000, // 30 days
    });
  };

  // Helper to clear auth cookies
  const clearAuthCookies = (res: Response) => {
    res.clearCookie('accessToken');
    res.clearCookie('refreshToken');
  };

  // Helper to get user by email
  const getUserByEmail = async (email: string): Promise<LocalUser | null> => {
    try {
      const result = await db.query<LocalUser>(
        'SELECT * FROM users WHERE email = $1', 
        [email]
      );
      return result.rows[0] || null;
    } catch (error) {
      logger.error('Error getting user by email:', error);
      throw error;
    }
  };

  // Helper to create a new user
  const createUser = async (userData: {
    email: string;
    name: string;
    passwordHash: string;
    verificationToken: string;
  }): Promise<LocalUser> => {
    try {
      const result = await db.query<LocalUser>(
        `INSERT INTO users (
          email, 
          name, 
          password_hash, 
          verification_token,
          verification_token_expires
        ) VALUES ($1, $2, $3, $4, NOW() + INTERVAL '24 hours')
        RETURNING *`,
        [
          userData.email,
          userData.name,
          userData.passwordHash,
          userData.verificationToken
        ]
      );
      
      return result.rows[0];
    } catch (error) {
      logger.error('Error creating user:', error);
      throw error;
    }
  };

  // Helper to validate user credentials
  const validateCredentials = async (email: string, password: string): Promise<LocalUser | null> => {
    try {
      const user = await getUserByEmail(email);
      if (!user || !user.password_hash) return null;
      
      const isMatch = await bcrypt.compare(password, user.password_hash);
      return isMatch ? user : null;
    } catch (error) {
      logger.error('Error validating credentials:', error);
      return null;
    }
  };

  // User login
  login: async (req: Request, res: Response, next: NextFunction) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
      }

      const { email, password } = req.body as LoginRequest;

      // Find user by email using the new database service
      const result = await db.query<LocalUser>(
        'SELECT * FROM users WHERE email = $1',
        [email]
      );

      const user = result.rows[0];

      // Check if user exists
      if (!user) {
        return res.status(401).json({ error: 'Invalid email or password' });
      }

      // Check if password is correct
      const isPasswordValid = await bcrypt.compare(password, user.password_hash);
      if (!isPasswordValid) {
        return res.status(401).json({ error: 'Invalid email or password' });
      }

      // Check if email is verified
      if (!user.is_verified) {
        return res.status(403).json({ 
          error: 'Email not verified',
          userId: user.id,
          email: user.email
        });
      }

      // Generate tokens
      const accessToken = generateAccessToken(user.id, user.email);
      const refreshToken = generateRefreshToken(user.id, user.email);

      // Hash the refresh token before storing in the database
      const refreshTokenHash = crypto
        .createHash('sha256')
        .update(refreshToken)
        .digest('hex');

      // Store the hashed refresh token in the database
      await db.query(
        'UPDATE users SET refresh_token_hash = $1 WHERE id = $2',
        [refreshTokenHash, user.id]
      );

      // Set cookies
      res.cookie(COOKIE_NAMES.ACCESS_TOKEN, accessToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: TOKEN_EXPIRATION.ACCESS * 1000, // Convert to milliseconds
      });

      res.cookie(COOKIE_NAMES.REFRESH_TOKEN, refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: TOKEN_EXPIRATION.REFRESH * 1000, // Convert to milliseconds
      });

      // Set authenticated cookie for client-side use
      res.cookie(COOKIE_NAMES.AUTHENTICATED, 'true', {
        httpOnly: false, // Allow client-side JavaScript to read
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        maxAge: TOKEN_EXPIRATION.REFRESH * 1000,
      });

      // Return user data without sensitive information
      const { password_hash, refresh_token_hash, ...userData } = user;

      const response: AuthResponse = {
        user: userData,
        accessToken,
        refreshToken,
        message: 'Login successful',
      };

      res.status(200).json(response);
    } catch (error) {
      logger.error('Login error:', error);
      next(error);
    }
  },

  // Register a new user
  const register = async (req: Request, res: Response) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { email, password, name } = req.body;
    
    // Validate input
    if (!email || !password || !name) {
      return res.status(400).json({ error: 'Email, password and name are required' });
    }
    
    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ error: 'Invalid email format' });
    }
    
    // Validate password strength
    if (password.length < 8) {
      return res.status(400).json({ 
        error: 'Password must be at least 8 characters long' 
      });
    }

    try {
      // Check if user already exists
      const existingUser = await getUserByEmail(email);
      if (existingUser) {
        return res.status(400).json({ 
          error: 'Email already in use',
          message: 'An account with this email already exists. Please use a different email or log in.'
        });
      }

      // Hash password
      const saltRounds = 10;
      const passwordHash = await bcrypt.hash(password, saltRounds);
      
      // Generate verification token
      const verificationToken = crypto.randomBytes(32).toString('hex');
      
      // Create user in database
      const newUser = await createUser({
        email,
        name,
        passwordHash,
        verificationToken
      });

      // Generate tokens
      const { accessToken, refreshToken } = generateTokens({
        userId: newUser.id,
        email: newUser.email
      });
      
      // Hash refresh token before storing
      const refreshTokenHash = hashToken(refreshToken);
      
      // Store refresh token in database
      await db.query(
        `UPDATE users 
         SET refresh_token_hash = $1, 
             updated_at = NOW() 
         WHERE id = $2`,
        [refreshTokenHash, newUser.id]
      );

      // Set HTTP-only cookies
      setTokenCookies(res, { accessToken, refreshToken });

      // Send verification email
      try {
        await sendVerificationEmail(email, {
          name,
          verificationLink: `${process.env.FRONTEND_URL}/verify-email?token=${verificationToken}`,
          token: verificationToken
        });
        logger.info(`Verification email sent to ${email}`);
      } catch (emailError) {
        logger.error('Failed to send verification email:', emailError);
        // Don't fail the request if email sending fails
      }

      // Return user data (without sensitive info)
      const userResponse = {
        id: newUser.id,
        email: newUser.email,
        name: newUser.name,
        is_verified: newUser.is_verified,
        created_at: newUser.created_at,
        updated_at: newUser.updated_at
      };

      return res.status(201).json({
        user: userResponse,
        accessToken,
        message: 'Registration successful! Please check your email to verify your account.'
      });
    } catch (error) {
      console.error('Registration error:', error);
      return res.status(500).json({ error: 'Internal server error' });
    }
  };

  // Login with email and password is now handled by the enhanced login function above

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
  refreshToken: async (req: Request, res: Response, next: NextFunction) => {
    try {
      const refreshToken = req.cookies[COOKIE_NAMES.REFRESH_TOKEN];

      if (!refreshToken) {
        return res.status(401).json({ error: 'Refresh token is required' });
      }

      // Verify the refresh token
      const payload = jwt.verify(
        refreshToken, 
        process.env.REFRESH_TOKEN_SECRET || process.env.JWT_SECRET!
      ) as CustomJwtPayload;
      
      if (payload.type !== 'refresh') {
        return res.status(400).json({ error: 'Invalid token type' });
      }

      // Hash the incoming refresh token for comparison
      const refreshTokenHash = crypto
        .createHash('sha256')
        .update(refreshToken)
        .digest('hex');

      // Find user by ID with matching refresh token hash
      const userResult = await db.query<LocalUser>(
        'SELECT * FROM users WHERE id = $1 AND refresh_token_hash = $2',
        [payload.userId, refreshTokenHash]
      );
      
      const user = userResult.rows[0];

      if (!user) {
        return res.status(401).json({ error: 'Invalid refresh token' });
      }

      // Generate new tokens
      const newAccessToken = generateAccessToken(user.id, user.email);
      const newRefreshToken = generateRefreshToken(user.id, user.email);

      // Hash the new refresh token before storing
      const newRefreshTokenHash = crypto
        .createHash('sha256')
        .update(newRefreshToken)
        .digest('hex');

      // Update refresh token hash in database
      await db.query(
        'UPDATE users SET refresh_token_hash = $1, updated_at = NOW() WHERE id = $2',
        [newRefreshTokenHash, user.id]
      );

      // Set cookies with new tokens
      res.cookie(COOKIE_NAMES.ACCESS_TOKEN, newAccessToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: TOKEN_EXPIRATION.ACCESS * 1000,
      });

      res.cookie(COOKIE_NAMES.REFRESH_TOKEN, newRefreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: TOKEN_EXPIRATION.REFRESH * 1000,
      });

      // Set authenticated cookie for client-side use
      res.cookie(COOKIE_NAMES.AUTHENTICATED, 'true', {
        httpOnly: false,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        maxAge: TOKEN_EXPIRATION.REFRESH * 1000,
      });

      // Return the new access token in the response
      return res.status(200).json({
        accessToken: newAccessToken,
        refreshToken: newRefreshToken,
        user: {
          id: user.id,
          email: user.email,
          name: user.name,
          email_verified: user.email_verified,
        },
      });
    } catch (error) {
      if (error instanceof jwt.TokenExpiredError) {
        return res.status(401).json({ error: 'Refresh token has expired' });
      } else if (error instanceof jwt.JsonWebTokenError) {
        return res.status(401).json({ error: 'Invalid refresh token' });
      }
      logger.error('Refresh token error:', error);
      next(error);
    }
  },

  // Logout user by clearing refresh token
  logout: async (req: Request, res: Response, next: NextFunction) => {
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
