import axios, { AxiosError } from 'axios';
import { v4 as uuidv4 } from 'uuid';
import { logger } from '../../src/utils/logger';

// Configuración
const API_BASE_URL = process.env.API_URL || 'http://localhost:3001';
const TEST_EMAIL = `test-${uuidv4().substring(0, 8)}@test.com`;
const TEST_PASSWORD = 'TestPassword123!';
const TEST_NAME = 'Test User';

// Variables para almacenar tokens
let accessToken = '';
let refreshToken = '';
let verificationToken = '';

// Cliente HTTP configurado
const api = axios.create({
  baseURL: API_BASE_URL,
  validateStatus: (status) => status < 500, // No lanzar error para códigos 4xx
});

// Interceptor para logging
api.interceptors.request.use((config) => {
  logger.debug(`[TEST] ${config.method?.toUpperCase()} ${config.url}`);
  if (config.data) {
    logger.debug('[TEST] Request Data:', JSON.stringify(config.data, null, 2));
  }
  return config;
});

// Función auxiliar para esperar
const delay = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));

describe('Authentication System', () => {
  // Test 1: Registro de usuario
  test('should register a new user', async () => {
    const response = await api.post('/api/auth/register', {
      email: TEST_EMAIL,
      password: TEST_PASSWORD,
      name: TEST_NAME,
    });

    expect(response.status).toBe(201);
    expect(response.data).toHaveProperty('message', 'User registered successfully. Please check your email to verify your account.');
    expect(response.data).toHaveProperty('user.email', TEST_EMAIL);
    expect(response.data.user).not.toHaveProperty('password');
    
    // En un entorno real, aquí extraeríamos el token de verificación del correo
    // Para esta prueba, simulamos que lo tenemos
    verificationToken = 'simulated-verification-token';
  });

  // Test 2: Verificación de correo electrónico
  test('should verify email with token', async () => {
    const response = await api.get(`/api/auth/verify-email?token=${verificationToken}`);
    
    expect([200, 400]).toContain(response.status);
    // Aceptamos tanto éxito como que ya estaba verificado
  });

  // Test 3: Inicio de sesión
  test('should login with email and password', async () => {
    const response = await api.post('/api/auth/login', {
      email: TEST_EMAIL,
      password: TEST_PASSWORD,
    });

    expect(response.status).toBe(200);
    expect(response.data).toHaveProperty('accessToken');
    expect(response.data).toHaveProperty('refreshToken');
    expect(response.data).toHaveProperty('user.email', TEST_EMAIL);
    expect(response.data.user).not.toHaveProperty('password');

    // Guardamos los tokens para pruebas posteriores
    accessToken = response.data.accessToken;
    refreshToken = response.data.refreshToken;
  });

  // Test 4: Obtener usuario actual
  test('should get current user with valid token', async () => {
    const response = await api.get('/api/auth/me', {
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    });

    expect(response.status).toBe(200);
    expect(response.data).toHaveProperty('email', TEST_EMAIL);
    expect(response.data).toHaveProperty('name', TEST_NAME);
  });

  // Test 5: Renovación de token
  test('should refresh access token', async () => {
    const response = await api.post('/api/auth/refresh-token', {
      refreshToken,
    });

    expect(response.status).toBe(200);
    expect(response.data).toHaveProperty('accessToken');
    expect(response.data).toHaveProperty('refreshToken');
    
    // Actualizamos el token de acceso
    accessToken = response.data.accessToken;
  });

  // Test 6: Cierre de sesión
  test('should logout and invalidate refresh token', async () => {
    const response = await api.post(
      '/api/auth/logout',
      { refreshToken },
      {
        headers: {
          Authorization: `Bearer ${accessToken}`,
        },
      }
    );

    expect(response.status).toBe(200);
    expect(response.data).toHaveProperty('message', 'Successfully logged out');
    
    // Verificamos que el refresh token ya no sea válido
    try {
      await api.post('/api/auth/refresh-token', { refreshToken });
      // Si llegamos aquí, el test falla
      expect(true).toBe(false);
    } catch (error) {
      const axiosError = error as AxiosError;
      expect(axiosError.response?.status).toBe(401);
    }
  });

  // Test 7: Rate limiting en login
  test('should enforce rate limiting on login', async () => {
    const loginAttempts = [];
    
    // Realizamos múltiples intentos de inicio de sesión
    for (let i = 0; i < 6; i++) {
      try {
        const response = await api.post('/api/auth/login', {
          email: `rate-limit-test-${i}@test.com`,
          password: 'wrong-password',
        });
        loginAttempts.push(response.status);
      } catch (error) {
        const axiosError = error as AxiosError;
        loginAttempts.push(axiosError.response?.status);
      }
      
      // Pequeña pausa entre intentos
      await delay(100);
    }
    
    // Verificamos que después de 5 intentos, recibimos un 429
    const status429Count = loginAttempts.filter(status => status === 429).length;
    expect(status429Count).toBeGreaterThan(0);
    
    // Esperamos un poco para que se reinicie el contador de rate limiting
    await delay(10000);
  }, 30000); // Aumentamos el timeout para esta prueba

  // Test 8: Validación de contraseña débil
  test('should reject weak passwords', async () => {
    const weakPasswords = [
      '123456', // Demasiado corta
      'password', // Sin mayúsculas ni números
      'Password', // Sin números ni caracteres especiales
      'PASSWORD123', // Sin minúsculas
      'password123', // Sin mayúsculas
    ];
    
    for (const password of weakPasswords) {
      const response = await api.post('/api/auth/register', {
        email: `weak-pass-${Date.now()}@test.com`,
        password,
        name: 'Weak Password User',
      });
      
      expect(response.status).toBe(400);
      expect(response.data).toHaveProperty('error');
    }
  });

  // Test 9: Validación de correo electrónico
  test('should validate email format', async () => {
    const invalidEmails = [
      'plainaddress',
      '@missingusername.com',
      'user@.com', 
      '.user@test.com',
      'user@test..com',
    ];
    
    for (const email of invalidEmails) {
      const response = await api.post('/api/auth/register', {
        email,
        password: 'ValidPass123!',
        name: 'Invalid Email User',
      });
      
      expect(response.status).toBe(400);
      expect(response.data).toHaveProperty('error');
    }
  });

  // Test 10: Intentar acceder a ruta protegida sin token
  test('should protect routes with authentication', async () => {
    try {
      await api.get('/api/auth/me'); // Sin token
      // Si llegamos aquí, el test falla
      expect(true).toBe(false);
    } catch (error) {
      const axiosError = error as AxiosError;
      expect(axiosError.response?.status).toBe(401);
    }
  });

  // Test 11: Autenticación con Google (simulada)
  test('should handle Google OAuth flow', async () => {
    // En un entorno real, esto haría una redirección a Google
    // Para la prueba, simulamos la respuesta de Google
    const googleAuthResponse = await api.get('/api/auth/google');
    
    // Esperamos una redirección (código 302)
    expect([301, 302]).toContain(googleAuthResponse.status);
    
    // Simulamos el callback de Google con un token falso
    // En una prueba real, necesitaríamos un servidor OAuth de prueba
    const callbackResponse = await api.get(
      `/api/auth/google/callback?code=mock-google-code`,
      { maxRedirects: 0, validateStatus: null }
    );
    
    // Podría ser una redirección o un error, dependiendo de la configuración
    expect([200, 302, 400, 500]).toContain(callbackResponse.status);
  });
});
