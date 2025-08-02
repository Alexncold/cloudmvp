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
   * Optimized for small to medium files (loads entire file into memory)
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
   * Encrypts a video file using streaming for better memory efficiency with large files
   * @param inputPath Path to the input video file
   * @param outputPath Optional output path (defaults to inputPath + '.enc')
   * @param chunkSize Size of chunks to process at once (default: 10MB)
   */
  public static async encryptVideoFile(
    inputPath: string,
    outputPath?: string,
    chunkSize: number = 10 * 1024 * 1024 // 10MB chunks
  ): Promise<string> {
    if (!this.ENCRYPTION_KEY) {
      throw new Error('Encryption key not configured');
    }

    const output = outputPath || `${inputPath}.enc`;
    const iv = crypto.randomBytes(this.IV_LENGTH);
    const salt = crypto.randomBytes(this.SALT_LENGTH);
    
    try {
      // Derive a key from the password and salt
      const key = await this.deriveKey(this.ENCRYPTION_KEY, salt);
      
      // Create cipher
      const cipher = crypto.createCipheriv(this.ALGORITHM, key, iv);
      
      // Create read and write streams
      const readStream = fs.createReadStream(inputPath, { highWaterMark: chunkSize });
      const writeStream = fs.createWriteStream(`${output}.tmp`);
      
      // Write header (salt + iv)
      await new Promise((resolve, reject) => {
        writeStream.write(salt, error => error ? reject(error) : resolve(true));
      });
      
      await new Promise((resolve, reject) => {
        writeStream.write(iv, error => error ? reject(error) : resolve(true));
      });
      
      // Process file in chunks
      let totalEncrypted = 0;
      
      for await (const chunk of readStream) {
        const encryptedChunk = cipher.update(chunk);
        await new Promise((resolve, reject) => {
          writeStream.write(encryptedChunk, error => error ? reject(error) : resolve(true));
        });
        totalEncrypted += chunk.length;
        logger.debug(`Encrypted ${totalEncrypted} bytes of video data`, { inputPath });
      }
      
      // Finalize encryption
      const finalChunk = cipher.final();
      if (finalChunk.length > 0) {
        await new Promise((resolve, reject) => {
          writeStream.write(finalChunk, error => error ? reject(error) : resolve(true));
        });
      }
      
      // Write auth tag
      const authTag = cipher.getAuthTag();
      await new Promise((resolve, reject) => {
        writeStream.write(authTag, error => error ? reject(error) : resolve(true));
      });
      
      // Close the write stream
      await new Promise((resolve) => writeStream.end(resolve));
      
      // Rename temp file to final output
      await fs.promises.rename(`${output}.tmp`, output);
      
      // Optionally remove the original file
      if (outputPath) {
        await unlink(inputPath).catch(error => {
          logger.warn(`Could not remove original file ${inputPath}:`, error);
        });
      }
      
      logger.info(`Successfully encrypted video file: ${inputPath} -> ${output}`, {
        inputPath,
        outputPath: output,
        totalEncrypted
      });
      
      return output;
      
    } catch (error) {
      // Clean up any partial output on error
      try {
        if (await fs.promises.access(`${output}.tmp`).then(() => true).catch(() => false)) {
          await unlink(`${output}.tmp`);
        }
      } catch (cleanupError) {
        logger.error('Error during cleanup after encryption failure:', cleanupError);
      }
      
      logger.error('Error encrypting video file:', { 
        inputPath, 
        outputPath: output,
        error: error.message 
      });
      
      throw new Error(`Failed to encrypt video file: ${error.message}`);
    }
  }

  /**
   * Decrypts a file and saves it to the specified location
   * Optimized for small to medium files (loads entire file into memory)
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
      throw new Error(`Failed to decrypt file: ${error.message}`);
    }
  }

  /**
   * Decrypts a video file using streaming for better memory efficiency with large files
   * @param inputPath Path to the encrypted video file
   * @param outputPath Path to save the decrypted file
   * @param chunkSize Size of chunks to process at once (default: 10MB)
   */
  public static async decryptVideoFile(
    inputPath: string,
    outputPath: string,
    chunkSize: number = 10 * 1024 * 1024 // 10MB chunks
  ): Promise<string> {
    if (!this.ENCRYPTION_KEY) {
      throw new Error('Encryption key not configured');
    }

    const headerSize = this.SALT_LENGTH + this.IV_LENGTH;
    const authTagSize = 16; // GCM auth tag is always 16 bytes
    let fileHandle: fs.promises.FileHandle | null = null;
    let writeStream: fs.WriteStream | null = null;
    
    try {
      // Open the input file
      fileHandle = await fs.promises.open(inputPath, 'r');
      const { size: fileSize } = await fileHandle.stat();
      
      if (fileSize < headerSize + authTagSize) {
        throw new Error('File is too small to be a valid encrypted video');
      }
      
      // Read salt and IV from the beginning of the file
      const saltBuffer = Buffer.alloc(this.SALT_LENGTH);
      const ivBuffer = Buffer.alloc(this.IV_LENGTH);
      
      await fileHandle.read(saltBuffer, 0, this.SALT_LENGTH, 0);
      await fileHandle.read(ivBuffer, 0, this.IV_LENGTH, this.SALT_LENGTH);
      
      // Derive the key
      const key = await this.deriveKey(this.ENCRYPTION_KEY, saltBuffer);
      
      // Create decipher
      const decipher = crypto.createDecipheriv(this.ALGORITHM, key, ivBuffer);
      
      // Read the auth tag from the end of the file
      const authTag = Buffer.alloc(authTagSize);
      await fileHandle.read(authTag, 0, authTagSize, fileSize - authTagSize);
      decipher.setAuthTag(authTag);
      
      // Create write stream for decrypted output
      writeStream = fs.createWriteStream(outputPath);
      
      // Process file in chunks
      let position = headerSize;
      const encryptedDataSize = fileSize - headerSize - authTagSize;
      let totalDecrypted = 0;
      
      while (position < fileSize - authTagSize) {
        const chunkSizeToRead = Math.min(chunkSize, fileSize - authTagSize - position);
        const chunk = Buffer.alloc(chunkSizeToRead);
        
        const { bytesRead } = await fileHandle.read(chunk, 0, chunkSizeToRead, position);
        if (bytesRead === 0) break;
        
        const decryptedChunk = decipher.update(chunk);
        if (decryptedChunk.length > 0) {
          await new Promise((resolve, reject) => {
            if (!writeStream) return resolve(true);
            writeStream.write(decryptedChunk, error => error ? reject(error) : resolve(true));
          });
        }
        
        position += bytesRead;
        totalDecrypted += decryptedChunk.length;
        logger.debug(`Decrypted ${totalDecrypted} bytes of video data`, { inputPath });
      }
      
      // Finalize decryption
      const finalChunk = decipher.final();
      if (finalChunk.length > 0) {
        await new Promise((resolve, reject) => {
          if (!writeStream) return resolve(true);
          writeStream.write(finalChunk, error => error ? reject(error) : resolve(true));
        });
      }
      
      // Close the write stream
      await new Promise((resolve) => {
        if (!writeStream) return resolve(true);
        writeStream.end(resolve);
      });
      
      logger.info(`Successfully decrypted video file: ${inputPath} -> ${outputPath}`, {
        inputPath,
        outputPath,
        totalDecrypted
      });
      
      return outputPath;
      
    } catch (error) {
      // Clean up any partial output on error
      try {
        if (writeStream) {
          writeStream.destroy();
        }
        if (await fs.promises.access(outputPath).then(() => true).catch(() => false)) {
          await unlink(outputPath);
        }
      } catch (cleanupError) {
        logger.error('Error during cleanup after decryption failure:', cleanupError);
      }
      
      logger.error('Error decrypting video file:', { 
        inputPath, 
        outputPath,
        error: error.message 
      });
      
      throw new Error(`Failed to decrypt video file: ${error.message}`);
      
    } finally {
      // Clean up file handles
      if (fileHandle) {
        await fileHandle.close().catch(error => 
          logger.warn('Error closing file handle:', error)
        );
      }
      if (writeStream && !writeStream.destroyed) {
        writeStream.destroy();
      }
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
