import type { Config } from '@jest/types';

// Configuración de Jest para TypeScript
const config: Config.InitialOptions = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  verbose: true,
  testMatch: ['**/test/**/*.test.ts'],
  collectCoverage: true,
  coverageDirectory: 'coverage',
  coverageReporters: ['text', 'lcov'],
  coveragePathIgnorePatterns: [
    '/node_modules/',
    '/dist/',
    '/test/'
  ],
  moduleNameMapper: {
    '^@shared/(.*)$': '<rootDir>/../shared/src/$1',
  },
  transform: {
    '^.+\\.tsx?$': ['ts-jest', {
      tsconfig: 'tsconfig.json',
      isolatedModules: true,
    }],
  },
  moduleFileExtensions: ['ts', 'tsx', 'js', 'jsx', 'json', 'node'],
  // Configuración de logs para depuración
  setupFilesAfterEnv: ['<rootDir>/test/setup.ts'],
  // Tiempo de espera para las pruebas (30 segundos)
  testTimeout: 30000,
};

export default config;
