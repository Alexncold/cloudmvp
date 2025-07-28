import bcrypt from 'bcryptjs';
import { v4 as uuidv4 } from 'uuid';
import { db } from './database';
import { logger } from '../utils/logger';
import { User, AuthTokens } from '../../../shared/types/auth';
import { generateToken, verifyToken, TokenType } from '../utils/jwt';

/**
 * Authentication service responsible for user registration, login, token management,
 * and authentication-related operations.
 * 
 * @class AuthService
 * @static
 */

export class AuthService {
  /** Number of salt rounds for password hashing */
  private static readonly SALT_ROUNDS = 10;
  
  /** Access token expiration time */
  private static readonly ACCESS_TOKEN_EXPIRES_IN = '15m';
  
  /** Refresh token expiration time */
  private static readonly REFRESH_TOKEN_EXPIRES_IN = '7d';

  /**
   * Registers a new user with the provided credentials.
   * 
   * @param {string} email - User's email address (must be unique)
   * @param {string} password - User's password (will be hashed)
   * @param {string} name - User's full name
   * @returns {Promise<User>} The created user object (without password)
   * @throws {Error} If email is already in use or registration fails
   * 
   * @example
   * const user = await AuthService.register('user@example.com', 'password123', 'John Doe');
   */
  public static async register(email: string, password: string, name: string): Promise<User> {
    try {
      // Verificar si el usuario ya existe
      const existingUser = await this.getUserByEmail(email);
      if (existingUser) {
        throw new Error('El correo electrónico ya está en uso');
      }

      // Hashear la contraseña
      const hashedPassword = await bcrypt.hash(password, this.SALT_ROUNDS);

      // Crear el usuario
      const result = await db.query(
        `INSERT INTO users (email, name, password_hash, is_verified)
         VALUES ($1, $2, $3, $4)
         RETURNING id, email, name, is_verified, created_at, updated_at`,
        [email, name, hashedPassword, false]
      );

      return result.rows[0];
    } catch (error) {
      logger.error('Error en el registro de usuario:', error);
      throw error;
    }
  }

  /**
   * Authenticates a user with email and password.
   * 
   * @param {string} email - User's email address
   * @param {string} password - User's password
   * @returns {Promise<{user: User, tokens: AuthTokens}>} User object and authentication tokens
   * @throws {Error} If credentials are invalid or account is locked
   * 
   * @example
   * const { user, tokens } = await AuthService.login('user@example.com', 'password123');
   */
  public static async login(email: string, password: string): Promise<{ user: User; tokens: AuthTokens }> {
    try {
      // Obtener el usuario por email
      const user = await this.getUserByEmail(email);
      if (!user) {
        throw new Error('Credenciales inválidas');
      }

      /**
       * Verifies if the provided password matches the stored hash.
       * 
       * @param {string} password - The plain text password to verify
       * @param {string} hashedPassword - The hashed password to compare against
       * @returns {Promise<boolean>} True if the password matches, false otherwise
       * 
       * @example
       * const isValid = await AuthService.verifyPassword('password123', hashedPassword);
       */
      const isPasswordValid = await bcrypt.compare(password, user.password_hash);
      if (!isPasswordValid) {
        throw new Error('Credenciales inválidas');
      }

      // Generar tokens
      const tokens = await this.generateTokens(user.id, user.email);

      // Devolver el usuario (sin la contraseña) y los tokens
      const { password_hash, ...userWithoutPassword } = user;
      return {
        user: userWithoutPassword,
        tokens
      };
    } catch (error) {
      logger.error('Error en el inicio de sesión:', error);
      throw error;
    }
  }

  /**
   * Refresca el token de acceso
   * 
   * Verifies and decodes a JWT token.
   * 
   * @param {string} token - The JWT token to verify
   * @param {TokenType} type - The expected token type (ACCESS or REFRESH)
   * @returns {Promise<{userId: string, type: string}>} Decoded token payload
   * @throws {Error} If token is invalid, expired, or of wrong type
   * 
   * @example
   * const payload = await AuthService.verifyToken(accessToken, TokenType.ACCESS);
   */
  public static async refreshToken(refreshToken: string): Promise<AuthTokens> {
    try {
      // Verificar el token de refresco
      const payload = verifyToken(refreshToken, 'refresh');
      if (!payload || !payload.userId || !payload.email) {
        throw new Error('Token de refresco inválido');
      }

      // Verificar que el usuario exista
      const user = await this.getUserById(payload.userId);
      if (!user) {
        throw new Error('Usuario no encontrado');
      }

      // Generar nuevos tokens
      return this.generateTokens(user.id, user.email);
    } catch (error) {
      logger.error('Error al refrescar el token:', error);
      throw error;
    }
  }

  /**
   * Retrieves a user by their ID.
   * 
   * @param {string} userId - The ID of the user to retrieve
   * @returns {Promise<User | null>} The user object or null if not found
   * 
   * @example
   * const user = await AuthService.getUserById('123e4567-e89b-12d3-a456-426614174000');
   */
  public static async getUserById(userId: string): Promise<User | null> {
    try {
      const result = await db.query(
        'SELECT id, email, name, google_id as "googleId", drive_folder_id as "driveFolderId", is_verified as "isVerified", created_at as "createdAt", updated_at as "updatedAt" FROM users WHERE id = $1',
        [userId]
      );
      return result.rows[0] || null;
    } catch (error) {
      logger.error('Error al obtener usuario por ID:', error);
      throw error;
    }
  }

  /**
   * Retrieves a user by their email address.
   * 
   * @param {string} email - The email address to search for
   * @returns {Promise<User | null>} The user object or null if not found
   * 
   * @example
   * const user = await AuthService.getUserByEmail('user@example.com');
   */
  private static async getUserByEmail(email: string): Promise<(User & { password_hash: string }) | null> {
    try {
      const result = await db.query(
        'SELECT * FROM users WHERE email = $1',
        [email]
      );
      return result.rows[0] || null;
    } catch (error) {
      logger.error('Error al obtener usuario por email:', error);
      throw error;
    }
  }

  /**
   * Generates access and refresh tokens for a user.
   * 
   * @param {string} userId - The ID of the user to generate tokens for
   * @returns {Promise<AuthTokens>} Object containing access and refresh tokens
   * 
   * @example
   * const tokens = await AuthService.generateTokens('123e4567-e89b-12d3-a456-426614174000');
   */
  private static async generateTokens(userId: string, email: string): Promise<AuthTokens> {
    try {
      const accessToken = generateToken(
        { userId, email, type: 'access' },
        this.ACCESS_TOKEN_EXPIRES_IN
      );

      const refreshToken = generateToken(
        { userId, email, type: 'refresh' },
        this.REFRESH_TOKEN_EXPIRES_IN
      );

      return {
        accessToken,
        refreshToken,
        expiresIn: 15 * 60 // 15 minutos en segundos
      };
    } catch (error) {
      logger.error('Error al generar tokens:', error);
      throw error;
    }
  }
}
