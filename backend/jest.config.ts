// @ts-check

/** @type {import('@jest/types').Config.InitialOptions} */
const config = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  verbose: true,
  // Deshabilitar watch por defecto
  watch: false,
  // Forzar salida después de las pruebas
  forceExit: true,
  // Limpiar mocks entre pruebas
  clearMocks: true,
  // Restablecer mocks entre pruebas
  resetMocks: true,
  // Restaurar implementaciones de mocks entre pruebas
  restoreMocks: true,
  
  collectCoverage: true,
  coverageDirectory: 'coverage',
  coverageReporters: ['text', 'lcov', 'clover'],
  coveragePathIgnorePatterns: [
    '/node_modules/'
  ],
  
  moduleNameMapper: {
    '^@shared/(.*)$': '<rootDir>/../shared/src/$1',
  },
  
  // Look for test files in these directories
  roots: [
    '<rootDir>/test/integration',
    '<rootDir>/test/unit'
  ],
  
  // Test file patterns to match
  testMatch: [
    '**/*.test.ts',
    '**/*.integration.test.ts'
  ],
  
  transform: {
    '^.+\\.tsx?$': ['ts-jest', {
      tsconfig: 'tsconfig.json',
      isolatedModules: true,
    }],
  },
  
  moduleFileExtensions: ['ts', 'tsx', 'js', 'jsx', 'json', 'node'],
  
  // Tiempos de espera más ajustados
  testTimeout: 15000, // 15 segundos
  
  setupFilesAfterEnv: ['<rootDir>/test/setup.ts'],
  globalSetup: '<rootDir>/test/global-setup.ts',
  globalTeardown: '<rootDir>/test/global-teardown.ts',
  
  // Deshabilitar workers para ejecutar pruebas secuencialmente
  maxWorkers: 1,
  
  // Reportes más simples para depuración
  reporters: [
    'default'
  ],
  
  // Configuración para detectar fugas de memoria
  detectOpenHandles: true,
  logHeapUsage: true,
  
  // Configuración de cobertura
  collectCoverageFrom: [
    'src/**/*.{ts,tsx}',
    '!**/node_modules/**',
    '!**/test/**',
    '!**/*.d.ts'
  ]
};

module.exports = config;
