import type { Request, Response, NextFunction } from 'express';
import { validationResult } from 'express-validator';
import bcrypt from 'bcryptjs';
import { v4 as uuidv4 } from 'uuid';
import crypto from 'crypto';
import { db } from '../services/database';
import { logger } from '../utils/logger';
import { 
  generateAccessToken, 
  generateRefreshToken,
  generateToken,
  verifyToken,
  type TokenPayload,
  TokenExpiredError,
  JsonWebTokenError,
  type TokenType
} from '../utils/jwt';
import { sendVerificationEmail, sendPasswordResetEmail } from '../services/emailService';

// Constants for token expiration times (in seconds)
const TOKEN_EXPIRATION = {
  ACCESS: 15 * 60, // 15 minutes
  REFRESH: 7 * 24 * 60 * 60, // 7 days
  EMAIL_VERIFICATION: 24 * 60 * 60, // 24 hours
  PASSWORD_RESET: 2 * 60 * 60 // 2 hours
} as const;

// Cookie names
const COOKIE_NAMES = {
  ACCESS_TOKEN: 'access_token',
  REFRESH_TOKEN: 'refresh_token',
  AUTHENTICATED: 'authenticated'
} as const;

// Define types locally since we're having issues with the auth types import
interface AuthTokens {
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
}

interface LocalUser {
  id: string;
  email: string;
  name: string;
  password_hash: string;
  is_verified: boolean;
  verification_token?: string | null;
  verification_token_expires?: Date | null;
  reset_password_token?: string | null;
  reset_password_expires?: Date | null;
  refresh_token_hash?: string | null;
  created_at: Date;
  updated_at: Date;
}

type RegisterRequest = {
  email: string;
  password: string;
  name: string;
};

type LoginRequest = {
  email: string;
  password: string;
};

type RefreshTokenRequest = {
  refreshToken: string;
};

type ForgotPasswordRequest = {
  email: string;
};

type ResetPasswordRequest = {
  token: string;
  password: string;
};

type VerifyEmailRequest = {
  token: string;
};

// Extend Express Request type to include user
declare module 'express-serve-static-core' {
  interface Request {
    user?: LocalUser;
  }
}

// Create a class for the auth controller
export class AuthController {
  private emailService = {
    sendVerificationEmail: sendVerificationEmail,
    sendPasswordResetEmail: sendPasswordResetEmail
  };

  constructor() {}

  // Factory function to create an instance of AuthController
  public static create(): AuthController {
    return new AuthController();
  }

  // Helper to generate tokens with proper typing
  private generateTokens = (userId: string, email: string): AuthTokens => {
    const accessToken = generateAccessToken(userId, email);
    const refreshToken = generateRefreshToken(userId, email);
    
    return {
      accessToken,
      refreshToken,
      expiresIn: TOKEN_EXPIRATION.ACCESS
    };
  }

  // Helper to generate a specific type of token
  private generateToken = (userId: string, email: string, type: TokenType): string => {
    const payload: Omit<TokenPayload, 'iat' | 'exp'> = {
      userId,
      email,
      type
    };
    
    switch (type) {
      case 'access':
        return generateAccessToken(userId, email);
      case 'refresh':
        return generateRefreshToken(userId, email);
      case 'email-verification':
      case 'password-reset':
        // Use the generic token generator for other token types
        return generateToken(payload, type === 'email-verification' 
          ? `${TOKEN_EXPIRATION.EMAIL_VERIFICATION}s` 
          : `${TOKEN_EXPIRATION.PASSWORD_RESET}s`);
      default:
        throw new Error(`Invalid token type: ${type}`);
    }
  }

  // Helper to hash tokens before storing them
  private hashToken = (token: string): string => {
    return crypto.createHash('sha256').update(token).digest('hex');
  }

  // Helper to set HTTP-only cookies for tokens
  private setTokenCookies = (res: Response, tokens: { accessToken: string; refreshToken: string }): void => {
    res.cookie(COOKIE_NAMES.ACCESS_TOKEN, tokens.accessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: TOKEN_EXPIRATION.ACCESS * 1000, // 15 minutes
    });

    // Set refresh token in HTTP-only cookie
    res.cookie(COOKIE_NAMES.REFRESH_TOKEN, tokens.refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: TOKEN_EXPIRATION.REFRESH * 1000, // 7 days
    });

    // Set authenticated flag in cookie
    res.cookie(COOKIE_NAMES.AUTHENTICATED, 'true', {
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: TOKEN_EXPIRATION.REFRESH * 1000, // Same as refresh token
    });
  }

  // Helper to create a new user
  private createUser = async (userData: {
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
          verification_token_expires,
          is_verified
        ) VALUES ($1, $2, $3, $4, NOW() + INTERVAL '24 hours', $5)
        RETURNING *`,
        [
          userData.email.toLowerCase(),
          userData.name,
          userData.passwordHash,
          this.hashToken(userData.verificationToken),
          false
        ]
      );
      return result.rows[0];
    } catch (error) {
      logger.error('Error creating user:', error);
      throw error;
    }
  }



  // Register a new user
  register = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        res.status(400).json({ errors: errors.array() });
        return;
      }

      const { email, password, name } = req.body as RegisterRequest;
      
      // Validate input
      if (!email || !password || !name) {
        res.status(400).json({ error: 'Email, password and name are required' });
        return;
      }
      
      // Validate email format
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!emailRegex.test(email)) {
        res.status(400).json({ error: 'Invalid email format' });
        return;
      }
      
      // Validate password strength
      if (password.length < 8) {
        res.status(400).json({ 
          error: 'Password must be at least 8 characters long' 
        });
        return;
      }

      // Check if user already exists
      const existingUser = await this.getUserByEmail(email);
      if (existingUser) {
        res.status(400).json({ 
          error: 'Email already in use',
          message: 'An account with this email already exists. Please use a different email or log in.'
        });
        return;
      }

      // Hash password
      const salt = await bcrypt.genSalt(10);
      const passwordHash = await bcrypt.hash(password, salt);
      
      // Generate verification token
      const verificationToken = crypto.randomBytes(32).toString('hex');
      
      // Create user in database
      const user = await this.createUser({
        email,
        name,
        passwordHash,
        verificationToken
      });

      // Send verification email
      try {
        await this.emailService.sendVerificationEmail(
          email,
          name,
          verificationToken
        );
      } catch (emailError) {
        logger.error('Failed to send verification email:', emailError);
        // Don't fail the registration if email sending fails
      }

      // Generate tokens
      const tokens = this.generateTokens(user.id, user.email);
      
      // Set HTTP-only cookies
      this.setTokenCookies(res, tokens);

      // Return user data (without sensitive info)
      const { password_hash, verification_token, refresh_token_hash, ...userData } = user;
      
      res.status(201).json({
        user: userData,
        accessToken: tokens.accessToken,
        refreshToken: tokens.refreshToken,
        expiresIn: tokens.expiresIn,
        message: 'Registration successful. Please check your email to verify your account.'
      });
    } catch (error) {
      logger.error('Error in register:', error);
      next(error);
    }
  }

  // User login
  login = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        res.status(400).json({ errors: errors.array() });
        return;
      }

      const { email, password } = req.body as LoginRequest;
      
      // Validate credentials
      const user = await this.validateCredentials(email, password);
      if (!user) {
        res.status(401).json({ 
          error: 'Invalid email or password',
          message: 'The email or password you entered is incorrect. Please try again.'
        });
        return;
      }

      // Check if email is verified
      if (!user.is_verified) {
        res.status(403).json({ 
          error: 'Email not verified',
          message: 'Please verify your email before logging in.'
        });
        return;
      }

      // Generate tokens
      const tokens = this.generateTokens(user.id, user.email);
      
      // Hash refresh token before storing
      const refreshTokenHash = this.hashToken(tokens.refreshToken);
      
      // Store refresh token in database
      await db.query(
        'UPDATE users SET refresh_token_hash = $1, updated_at = NOW() WHERE id = $2',
        [refreshTokenHash, user.id]
      );
      
      // Set HTTP-only cookies
      this.setTokenCookies(res, tokens);

      // Return user data (without sensitive info)
      const { password_hash, verification_token, refresh_token_hash, ...userData } = user;
      
      res.status(200).json({
        user: userData,
        accessToken: tokens.accessToken,
        refreshToken: tokens.refreshToken,
        expiresIn: tokens.expiresIn,
        message: 'Login successful'
      });
    } catch (error) {
      logger.error('Error in login:', error);
      next(error);
    }
  }

  // Verify user's email
  verifyEmail = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const { token } = req.params as unknown as VerifyEmailRequest;
      
      // Find user by verification token
      const user = await this.getUserByVerificationToken(token);
      if (!user) {
        res.status(400).json({ error: 'Invalid or expired verification token' });
        return;
      }
      
      // Update user as verified
      await db.query(
        'UPDATE users SET is_verified = true, verification_token = NULL WHERE id = $1',
        [user.id]
      );
      
      res.status(200).json({ message: 'Email verified successfully' });
    } catch (error) {
      logger.error('Email verification error:', error);
      next(error);
    }
  }

  // Refresh access token
  refreshToken = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const { refreshToken } = req.body as RefreshTokenRequest;
      
      if (!refreshToken) {
        res.status(400).json({ error: 'Refresh token is required' });
        return;
      }
      
      // Verify refresh token
      const decoded = verifyToken(refreshToken, 'refresh') as TokenPayload;
      
      // Find user by ID from token
      const user = await this.getUserById(decoded.userId);
      
      if (!user || !user.refresh_token_hash) {
        res.status(401).json({ error: 'Invalid refresh token' });
        return;
      }
      
      // Verify the stored refresh token hash matches
      const isTokenValid = await bcrypt.compare(refreshToken, user.refresh_token_hash);
      if (!isTokenValid) {
        res.status(401).json({ error: 'Invalid refresh token' });
        return;
      }
      
      // Generate new tokens
      const tokens = this.generateTokens(user.id, user.email);
      
      // Hash the new refresh token before storing
      const refreshTokenHash = this.hashToken(tokens.refreshToken);
      
      // Update refresh token in database
      await db.query(
        'UPDATE users SET refresh_token_hash = $1, updated_at = NOW() WHERE id = $2',
        [refreshTokenHash, user.id]
      );
      
      // Set HTTP-only cookies
      this.setTokenCookies(res, tokens);
      
      // Return new tokens
      res.status(200).json({
        accessToken: tokens.accessToken,
        refreshToken: tokens.refreshToken,
        expiresIn: tokens.expiresIn,
        tokenType: 'Bearer'
      });
      
    } catch (error) {
      if (error instanceof TokenExpiredError) {
        res.status(401).json({ error: 'Refresh token has expired' });
      } else if (error instanceof JsonWebTokenError) {
        res.status(401).json({ error: 'Invalid refresh token' });
      } else {
        logger.error('Error in refreshToken:', error);
        next(error);
      }
    }
  }

  // Logout user
  logout = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    const { refreshToken } = req.cookies;

    if (!refreshToken) {
      this.clearAuthCookies(res);
      res.status(200).json({ message: 'Logged out successfully' });
      return;
    }

    try {
      // Verify the refresh token to get user ID
      const payload = verifyToken(refreshToken, 'refresh') as TokenPayload;
      
      if (payload && payload.userId) {
        // Clear the refresh token from the database
        await db.query(
          `UPDATE users 
           SET refresh_token_hash = NULL, 
               updated_at = NOW() 
           WHERE id = $1`,
          [payload.userId]
        );
      }
    } catch (error) {
      // If token is invalid, still clear the cookies
      if (error instanceof TokenExpiredError) {
        logger.warn('Expired refresh token during logout');
      } else if (error instanceof JsonWebTokenError) {
        logger.warn('Invalid refresh token during logout');
      } else {
        logger.error('Error during logout:', error);
      }
    }

    // Clear the auth cookies
    this.clearAuthCookies(res);
    
    res.status(200).json({ 
      success: true,
      message: 'Logged out successfully' 
    });
  };

  // Get current authenticated user
  getCurrentUser = (req: Request, res: Response): void => {
    if (!req.user) {
      res.status(401).json({ 
        error: 'Not authenticated',
        message: 'You must be logged in to access this resource'
      });
      return;
    }

    // Return user data without sensitive information
    const { 
      id, 
      email, 
      name, 
      is_verified, 
      created_at, 
      updated_at,
      password_hash,
      refresh_token_hash,
      verification_token,
      ...rest
    } = req.user;
    
    res.status(200).json({
      user: {
        id,
        email,
        name,
        is_verified,
        created_at,
        updated_at,
        ...rest
      }
    });
  };

  // Forgot password
  forgotPassword = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const { email } = req.body as ForgotPasswordRequest;
      
      if (!email) {
        res.status(400).json({ error: 'Email is required' });
        return;
      }
      
      // Find user by email
      const user = await this.getUserByEmail(email);
      if (!user) {
        // Don't reveal that the email doesn't exist for security reasons
        res.status(200).json({ message: 'If an account exists with this email, a password reset link has been sent' });
        return;
      }
      
      // Generate password reset token
      const resetToken = crypto.randomBytes(32).toString('hex');
      const resetTokenExpires = new Date(Date.now() + TOKEN_EXPIRATION.PASSWORD_RESET * 1000);
      
      // Update user with reset token
      await db.query(
        'UPDATE users SET reset_token = $1, reset_token_expires = $2, updated_at = NOW() WHERE id = $3',
        [this.hashToken(resetToken), resetTokenExpires, user.id]
      );
      
      // Send password reset email
      try {
        await this.emailService.sendPasswordResetEmail(
          email,
          user.name,
          resetToken
        );
      } catch (emailError) {
        logger.error('Failed to send password reset email:', emailError);
        // Don't fail the request if email sending fails
      }
      
      res.status(200).json({ 
        message: 'If an account exists with this email, a password reset link has been sent' 
      });
    } catch (error) {
      logger.error('Error in forgotPassword:', error);
      next(error);
    }
  };

  // Reset password
  resetPassword = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const { token } = req.params;
      const { password } = req.body as ResetPasswordRequest;
      
      if (!token) {
        res.status(400).json({ error: 'Reset token is required' });
        return;
      }
      
      if (!password) {
        res.status(400).json({ error: 'New password is required' });
        return;
      }
      
      // Find user by reset token
      const result = await db.query<LocalUser>(
        'SELECT * FROM users WHERE reset_token = $1 AND reset_token_expires > NOW()',
        [this.hashToken(token)]
      );
      
      const user = result.rows[0];
      if (!user) {
        res.status(400).json({ error: 'Invalid or expired reset token' });
        return;
      }
      
      // Hash new password
      const salt = await bcrypt.genSalt(10);
      const passwordHash = await bcrypt.hash(password, salt);
      
      // Update user password and clear reset token
      await db.query(
        'UPDATE users SET password_hash = $1, reset_token = NULL, reset_token_expires = NULL, updated_at = NOW() WHERE id = $2',
        [passwordHash, user.id]
      );
      
      // Invalidate all refresh tokens for this user
      await db.query(
        'UPDATE users SET refresh_token_hash = NULL WHERE id = $1',
        [user.id]
      );
      
      // Clear auth cookies
      this.clearAuthCookies(res);
      
      res.status(200).json({ message: 'Password reset successful' });
    } catch (error) {
      logger.error('Error in resetPassword:', error);
      next(error);
    }
  };



  // Helper to hash tokens before storing them
  // Helper to clear auth cookies
  private clearAuthCookies = (res: Response): void => {
    res.clearCookie(COOKIE_NAMES.ACCESS_TOKEN);
    res.clearCookie(COOKIE_NAMES.REFRESH_TOKEN);
    res.clearCookie(COOKIE_NAMES.AUTHENTICATED);
  };

  // Helper to validate user credentials
  private validateCredentials = async (email: string, password: string): Promise<LocalUser | null> => {
    try {
      const user = await this.getUserByEmail(email);
      if (!user) return null;

      const isMatch = await bcrypt.compare(password, user.password_hash);
      return isMatch ? user : null;
    } catch (error) {
      logger.error('Error validating credentials:', error);
      return null;
    }
  };

  // Helper to get user by verification token
  private getUserByVerificationToken = async (token: string): Promise<LocalUser | null> => {
    try {
      const result = await db.query<LocalUser>(
        'SELECT * FROM users WHERE verification_token = $1 AND verification_token_expires > NOW()',
        [this.hashToken(token)]
      );
      return result.rows[0] || null;
    } catch (error) {
      logger.error('Error getting user by verification token:', error);
      return null;
    }
  };

  // Helper to get user by ID
  private getUserById = async (userId: string): Promise<LocalUser | null> => {
    try {
      const result = await db.query<LocalUser>(
        'SELECT * FROM users WHERE id = $1',
        [userId]
      );
      return result.rows[0] || null;
    } catch (error) {
      logger.error('Error getting user by ID:', error);
      return null;
    }
  };

  // Helper to get user by email
  private getUserByEmail = async (email: string): Promise<LocalUser | null> => {
    try {
      const result = await db.query<LocalUser>(
        'SELECT * FROM users WHERE email = $1',
        [email.toLowerCase()]
      );
      return result.rows[0] || null;
    } catch (error) {
      logger.error('Error getting user by email:', error);
      return null;
    }
  };


}

// Create a factory function for backward compatibility
function createAuthController(): AuthController {
  return new AuthController();
}

export default createAuthController;
