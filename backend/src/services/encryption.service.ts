import crypto from 'crypto';
import fs from 'fs';
import { promisify } from 'util';
import { logger } from '../utils/logger';
import path from 'path';

const readFile = promisify(fs.readFile);
const writeFile = promisify(fs.writeFile);
const unlink = promisify(fs.unlink);

export class EncryptionService {
  private static readonly ALGORITHM = 'aes-256-gcm';
  private static readonly IV_LENGTH = 16; // 16 bytes for AES-GCM
  private static readonly SALT_LENGTH = 64; // 64 bytes for PBKDF2
  private static readonly KEY_LENGTH = 32; // 32 bytes for AES-256
  private static readonly ITERATIONS = 100000;
  private static readonly DIGEST = 'sha512';
  private static readonly ENCRYPTION_KEY = process.env.AES_ENCRYPTION_KEY;

  /**
   * Derives a key from a password using PBKDF2
   */
  private static async deriveKey(
    password: string,
    salt: Buffer
  ): Promise<Buffer> {
    return new Promise((resolve, reject) => {
      crypto.pbkdf2(
        password,
        salt,
        this.ITERATIONS,
        this.KEY_LENGTH,
        this.DIGEST,
        (err, derivedKey) => {
          if (err) reject(err);
          else resolve(derivedKey);
        }
      );
    });
  }

  /**
   * Encrypts sensitive text data (like credentials)
   */
  public static async encryptText(plaintext: string): Promise<string> {
    try {
      if (!this.ENCRYPTION_KEY) {
        throw new Error('Encryption key not configured');
      }

      const iv = crypto.randomBytes(this.IV_LENGTH);
      const salt = crypto.randomBytes(this.SALT_LENGTH);
      
      // Derive a key from the password and salt
      const key = await this.deriveKey(this.ENCRYPTION_KEY, salt);
      
      // Create cipher
      const cipher = crypto.createCipheriv(this.ALGORITHM, key, iv);
      
      // Encrypt the data
      const encrypted = Buffer.concat([
        cipher.update(plaintext, 'utf8'),
        cipher.final()
      ]);
      
      // Get the auth tag for GCM mode
      const authTag = cipher.getAuthTag();
      
      // Combine salt, iv, auth tag, and encrypted data
      const result = Buffer.concat([salt, iv, authTag, encrypted]);
      
      // Return as base64 string
      return result.toString('base64');
    } catch (error) {
      logger.error('Error encrypting text:', error);
      throw new Error('Failed to encrypt data');
    }
  }

  /**
   * Decrypts sensitive text data
   */
  public static async decryptText(encryptedText: string): Promise<string> {
    try {
      if (!this.ENCRYPTION_KEY) {
        throw new Error('Encryption key not configured');
      }

      // Convert from base64 to buffer
      const data = Buffer.from(encryptedText, 'base64');
      
      // Extract salt, iv, auth tag, and encrypted data
      const salt = data.slice(0, this.SALT_LENGTH);
      const iv = data.slice(this.SALT_LENGTH, this.SALT_LENGTH + this.IV_LENGTH);
      const authTag = data.slice(
        this.SALT_LENGTH + this.IV_LENGTH,
        this.SALT_LENGTH + this.IV_LENGTH + 16 // 16 bytes for GCM auth tag
      );
      const encrypted = data.slice(this.SALT_LENGTH + this.IV_LENGTH + 16);
      
      // Derive the key
      const key = await this.deriveKey(this.ENCRYPTION_KEY, salt);
      
      // Create decipher
      const decipher = crypto.createDecipheriv(this.ALGORITHM, key, iv);
      decipher.setAuthTag(authTag);
      
      // Decrypt the data
      const decrypted = Buffer.concat([
        decipher.update(encrypted),
        decipher.final()
      ]);
      
      return decrypted.toString('utf8');
    } catch (error) {
      logger.error('Error decrypting text:', error);
      throw new Error('Failed to decrypt data');
    }
  }

  /**
   * Encrypts a file and saves it with .enc extension
   */
  public static async encryptFile(
    inputPath: string,
    outputPath?: string
  ): Promise<string> {
    try {
      if (!this.ENCRYPTION_KEY) {
        throw new Error('Encryption key not configured');
      }

      const output = outputPath || `${inputPath}.enc`;
      const iv = crypto.randomBytes(this.IV_LENGTH);
      const salt = crypto.randomBytes(this.SALT_LENGTH);
      
      // Derive a key from the password and salt
      const key = await this.deriveKey(this.ENCRYPTION_KEY, salt);
      
      // Create cipher
      const cipher = crypto.createCipheriv(this.ALGORITHM, key, iv);
      
      // Read the input file
      const data = await readFile(inputPath);
      
      // Encrypt the data
      const encrypted = Buffer.concat([
        cipher.update(data),
        cipher.final()
      ]);
      
      // Get the auth tag for GCM mode
      const authTag = cipher.getAuthTag();
      
      // Combine salt, iv, auth tag, and encrypted data
      const result = Buffer.concat([salt, iv, authTag, encrypted]);
      
      // Write the encrypted data to the output file
      await writeFile(output, result);
      
      // Optionally remove the original file
      if (outputPath) {
        await unlink(inputPath).catch(error => {
          logger.warn(`Could not remove original file ${inputPath}:`, error);
        });
      }
      
      return output;
    } catch (error) {
      logger.error('Error encrypting file:', { inputPath, error });
      throw new Error('Failed to encrypt file');
    }
  }

  /**
   * Decrypts a file and saves it to the specified location
   */
  public static async decryptFile(
    inputPath: string,
    outputPath: string
  ): Promise<string> {
    try {
      if (!this.ENCRYPTION_KEY) {
        throw new Error('Encryption key not configured');
      }

      // Read the encrypted file
      const data = await readFile(inputPath);
      
      // Extract salt, iv, auth tag, and encrypted data
      const salt = data.slice(0, this.SALT_LENGTH);
      const iv = data.slice(this.SALT_LENGTH, this.SALT_LENGTH + this.IV_LENGTH);
      const authTag = data.slice(
        this.SALT_LENGTH + this.IV_LENGTH,
        this.SALT_LENGTH + this.IV_LENGTH + 16 // 16 bytes for GCM auth tag
      );
      const encrypted = data.slice(this.SALT_LENGTH + this.IV_LENGTH + 16);
      
      // Derive the key
      const key = await this.deriveKey(this.ENCRYPTION_KEY, salt);
      
      // Create decipher
      const decipher = crypto.createDecipheriv(this.ALGORITHM, key, iv);
      decipher.setAuthTag(authTag);
      
      // Decrypt the data
      const decrypted = Buffer.concat([
        decipher.update(encrypted),
        decipher.final()
      ]);
      
      // Write the decrypted data to the output file
      await writeFile(outputPath, decrypted);
      
      return outputPath;
    } catch (error) {
      logger.error('Error decrypting file:', { inputPath, outputPath, error });
      throw new Error('Failed to decrypt file');
    }
  }

  /**
   * Generates a secure random string of specified length
   */
  public static generateRandomString(length: number = 32): string {
    return crypto.randomBytes(Math.ceil(length / 2))
      .toString('hex')
      .slice(0, length);
  }
}
