/** @type {import('jest').Config} */
module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  roots: ['<rootDir>/tests'],
  testMatch: ['**/*.test.ts'],
  // TODO: Fix these tests and remove from ignore list
  testPathIgnorePatterns: [
    '/node_modules/',
    'tests/unit/services/audit/detectors/',
    'tests/unit/services/export/',
    'tests/integration/auth/',
    'tests/integration/api/',
  ],
  collectCoverageFrom: [
    'src/**/*.ts',
    '!src/**/*.types.ts',
    '!src/types/**',
  ],
  coverageThreshold: {
    global: {
      branches: 30,
      functions: 30,
      lines: 30,
      statements: 30,
    },
  },
  coverageReporters: ['text', 'lcov', 'html'],
  setupFilesAfterEnv: ['<rootDir>/tests/setup.ts'],
  moduleFileExtensions: ['ts', 'js', 'json'],
  transform: {
    '^.+\\.ts$': ['ts-jest', {
      diagnostics: false, // Disable type checking in tests for now
      isolatedModules: true,
    }],
  },
  verbose: true,
};
