import request from 'supertest';
import app from '../src/app';
import { createAuthController } from '../src/controllers/authController';
import { Pool } from 'pg';
import { v4 as uuidv4 } from 'uuid';

// Mock database connection for testing
const testDbConfig = {
  user: process.env.TEST_DB_USER || 'postgres',
  host: process.env.TEST_DB_HOST || 'localhost',
  database: process.env.TEST_DB_NAME || 'cloudcam_test',
  password: process.env.TEST_DB_PASSWORD || 'postgres',
  port: parseInt(process.env.TEST_DB_PORT || '5432'),
};

const pool = new Pool(testDbConfig);

// Test user data
const testUser = {
  email: `test-${uuidv4()}@example.com`,
  password: 'Test1234!',
  name: 'Test User',
};

// Test reset password data
const newPassword = 'NewTest1234!';
let resetToken: string;

describe('Password Recovery Flow', () => {
  beforeAll(async () => {
    // Create a test user
    await pool.query(
      'INSERT INTO users (email, password_hash, name, email_verified) VALUES ($1, $2, $3, true) RETURNING id',
      [testUser.email, 'hashed_password', testUser.name]
    );
  });

  afterAll(async () => {
    // Clean up test data
    await pool.query('DELETE FROM users WHERE email = $1', [testUser.email]);
    await pool.end();
  });

  describe('POST /api/auth/forgot-password', () => {
    it('should return 200 and send reset email for valid email', async () => {
      const response = await request(app)
        .post('/api/auth/forgot-password')
        .send({ email: testUser.email });

      expect(response.status).toBe(200);
      expect(response.body.message).toContain('se ha enviado un enlace');

      // Get the reset token from the database for testing
      const result = await pool.query(
        'SELECT password_reset_token FROM users WHERE email = $1',
        [testUser.email]
      );
      resetToken = result.rows[0].password_reset_token;
      expect(resetToken).toBeDefined();
    });

    it('should return 200 even for non-existent email (security measure)', async () => {
      const response = await request(app)
        .post('/api/auth/forgot-password')
        .send({ email: 'nonexistent@example.com' });

      expect(response.status).toBe(200);
    });

    it('should return 400 for invalid email format', async () => {
      const response = await request(app)
        .post('/api/auth/forgot-password')
        .send({ email: 'invalid-email' });

      expect(response.status).toBe(400);
    });
  });

  describe('POST /api/auth/reset-password', () => {
    it('should return 200 and update password with valid token', async () => {
      const response = await request(app)
        .post('/api/auth/reset-password')
        .send({
          token: resetToken,
          password: newPassword,
        });

      expect(response.status).toBe(200);
      expect(response.body.message).toBe('Contraseña actualizada exitosamente');

      // Verify password was updated
      const result = await pool.query(
        'SELECT password_hash FROM users WHERE email = $1',
        [testUser.email]
      );
      expect(result.rows[0].password_hash).not.toBe('hashed_password');
    });

    it('should return 400 for invalid token', async () => {
      const response = await request(app)
        .post('/api/auth/reset-password')
        .send({
          token: 'invalid-token',
          password: newPassword,
        });

      expect(response.status).toBe(400);
      expect(response.body.error).toContain('Token inválido o expirado');
    });

    it('should return 400 for invalid password', async () => {
      const response = await request(app)
        .post('/api/auth/reset-password')
        .send({
          token: resetToken,
          password: 'weak',
        });

      expect(response.status).toBe(400);
      expect(response.body.errors).toBeDefined();
    });
  });
});
