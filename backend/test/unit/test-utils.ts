// Utilidades para pruebas unitarias

export const testUser = {
  id: '550e8400-e29b-41d4-a716-446655440000',
  email: 'test@example.com',
  name: 'Test User',
  password: 'TestPassword123!',
  passwordHash: '$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW', // hash de 'secret'
  isVerified: true,
  createdAt: new Date(),
  updatedAt: new Date(),
};

export const testTokens = {
  accessToken: 'test-access-token',
  refreshToken: 'test-refresh-token',
  verificationToken: 'test-verification-token',
};

export const mockJwtVerify = jest.fn();

export const setupJwtMocks = () => {
  jest.mock('jsonwebtoken', () => ({
    sign: jest.fn(() => 'mocked-token'),
    verify: mockJwtVerify,
  }));
};

export const setupCryptoMocks = () => {
  jest.mock('../../src/utils/crypto', () => ({
    hashPassword: jest.fn((password) => Promise.resolve(`hashed-${password}`)),
    verifyPassword: jest.fn(() => Promise.resolve(true)),
    encrypt: jest.fn((text) => `encrypted-${text}`),
    hashToken: jest.fn((token) => `hashed-${token}`),
  }));
};

export const setupEmailServiceMocks = () => {
  jest.mock('../../src/services/emailService', () => ({
    sendVerificationEmail: jest.fn(() => Promise.resolve()),
  }));
};
