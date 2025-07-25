import crypto from 'crypto';
import bcrypt from 'bcrypt';
import { logger } from './logger';

// Configuration
const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 16;
const AUTH_TAG_LENGTH = 16;
const SALT_ROUNDS = 12;
const ENCODING = 'hex' as const;

// Get encryption key from environment variables
const ENCRYPTION_KEY = process.env.AES_SECRET;

if (!ENCRYPTION_KEY || ENCRYPTION_KEY.length < 32) {
  logger.warn('AES_SECRET is not set or too short. Using a default key (NOT SECURE FOR PRODUCTION)');
}

// Ensure the key is 32 bytes (256 bits)
const getValidKey = (): string => {
  if (!ENCRYPTION_KEY) {
    return 'default-key-must-be-32-bytes-long!'; // Only for development
  }
  // Pad or truncate the key to 32 bytes
  return Buffer.from(ENCRYPTION_KEY).subarray(0, 32).toString('hex').padEnd(32, '0');
};

const key = Buffer.from(getValidKey(), 'hex');

/**
 * Encrypts sensitive text (like Google refresh tokens)
 * @param text - The text to encrypt
 * @returns Encrypted text in format: iv:authTag:encryptedData
 */
export function encrypt(text: string): string {
  try {
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv(ALGORITHM, key, iv, { authTagLength: AUTH_TAG_LENGTH });
    
    let encrypted = cipher.update(text, 'utf8', ENCODING);
    encrypted += cipher.final(ENCODING);
    const authTag = cipher.getAuthTag();
    
    // Format: iv:authTag:encrypted
    return `${iv.toString(ENCODING)}:${authTag.toString(ENCODING)}:${encrypted}`;
  } catch (error) {
    logger.error('Encryption failed:', error);
    throw new Error('Encryption failed');
  }
}

/**
 * Decrypts previously encrypted text
 * @param encryptedText - The encrypted text in format: iv:authTag:encryptedData
 * @returns Decrypted text
 */
export function decrypt(encryptedText: string): string {
  try {
    const [ivHex, authTagHex, encrypted] = encryptedText.split(':');
    
    if (!ivHex || !authTagHex || !encrypted) {
      throw new Error('Invalid encrypted text format');
    }
    
    const iv = Buffer.from(ivHex, ENCODING);
    const authTag = Buffer.from(authTagHex, ENCODING);
    
    const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
    decipher.setAuthTag(authTag);
    
    let decrypted = decipher.update(encrypted, ENCODING, 'utf8');
    decrypted += decipher.final('utf8');
    
    return decrypted;
  } catch (error) {
    logger.error('Decryption failed:', error);
    throw new Error('Decryption failed - invalid or corrupted data');
  }
}

/**
 * Hashes a password using bcrypt
 * @param password - The password to hash
 * @returns Hashed password
 */
export async function hashPassword(password: string): Promise<string> {
  try {
    return await bcrypt.hash(password, SALT_ROUNDS);
  } catch (error) {
    logger.error('Password hashing failed:', error);
    throw new Error('Failed to hash password');
  }
}

/**
 * Verifies a password against a hash
 * @param password - The password to verify
 * @param hash - The hash to verify against
 * @returns Boolean indicating if the password matches the hash
 */
export async function verifyPassword(password: string, hash: string): Promise<boolean> {
  try {
    return await bcrypt.compare(password, hash);
  } catch (error) {
    logger.error('Password verification failed:', error);
    return false;
  }
}

/**
 * Generates a secure random token
 * @param length - Length of the token in bytes (default: 32)
 * @returns A secure random token in hex format
 */
export function generateSecureToken(length = 32): string {
  return crypto.randomBytes(length).toString('hex');
}

/**
 * Creates a cryptographic hash of a token for secure storage
 * @param token - The token to hash
 * @returns Hashed token
 */
export function hashToken(token: string): string {
  return crypto.createHash('sha256').update(token).digest('hex');
}
