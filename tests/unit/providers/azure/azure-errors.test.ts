/**
 * Azure Error Types Unit Tests
 *
 * Tests for Azure-specific error classes and error handling utilities.
 */

import {
  AzureError,
  AzureAuthenticationError,
  AzureAPIError,
  AzureRateLimitError,
  AzureTimeoutError,
  AzurePermissionError,
  AzureConfigurationError,
  AzureTokenExpiredError,
  isRetryableError,
} from '../../../../src/providers/azure/azure-errors';

describe('Azure Error Types', () => {
  describe('AzureError', () => {
    it('should create base Azure error', () => {
      const error = new AzureError('Test error');

      expect(error).toBeInstanceOf(Error);
      expect(error).toBeInstanceOf(AzureError);
      expect(error.name).toBe('AzureError');
      expect(error.message).toBe('Test error');
    });
  });

  describe('AzureAuthenticationError', () => {
    it('should create authentication error with context', () => {
      const error = new AzureAuthenticationError(
        'Auth failed',
        'tenant-123',
        'client-456'
      );

      expect(error).toBeInstanceOf(AzureError);
      expect(error.name).toBe('AzureAuthenticationError');
      expect(error.message).toBe('Auth failed');
      expect(error.tenantId).toBe('tenant-123');
      expect(error.clientId).toBe('client-456');
    });

    it('should store cause error', () => {
      const cause = new Error('Invalid credentials');
      const error = new AzureAuthenticationError(
        'Auth failed',
        'tenant-123',
        'client-456',
        cause
      );

      expect(error.cause).toBe(cause);
    });
  });

  describe('AzureAPIError', () => {
    it('should create API error with status code', () => {
      const error = new AzureAPIError('API failed', '/users', 500);

      expect(error).toBeInstanceOf(AzureError);
      expect(error.name).toBe('AzureAPIError');
      expect(error.endpoint).toBe('/users');
      expect(error.statusCode).toBe(500);
    });

    it('should create API error without status code', () => {
      const error = new AzureAPIError('API failed', '/groups');

      expect(error.endpoint).toBe('/groups');
      expect(error.statusCode).toBeUndefined();
    });
  });

  describe('AzureRateLimitError', () => {
    it('should create rate limit error with retry-after', () => {
      const error = new AzureRateLimitError('Rate limited', '/users', 60);

      expect(error).toBeInstanceOf(AzureError);
      expect(error.name).toBe('AzureRateLimitError');
      expect(error.endpoint).toBe('/users');
      expect(error.retryAfter).toBe(60);
    });
  });

  describe('AzureTimeoutError', () => {
    it('should create timeout error', () => {
      const error = new AzureTimeoutError('Timeout', 'GET /users', 30000);

      expect(error).toBeInstanceOf(AzureError);
      expect(error.name).toBe('AzureTimeoutError');
      expect(error.operation).toBe('GET /users');
      expect(error.timeoutMs).toBe(30000);
    });
  });

  describe('AzurePermissionError', () => {
    it('should create permission error with required permissions', () => {
      const error = new AzurePermissionError(
        'Insufficient permissions',
        '/users',
        ['User.Read.All', 'Directory.Read.All']
      );

      expect(error).toBeInstanceOf(AzureError);
      expect(error.name).toBe('AzurePermissionError');
      expect(error.endpoint).toBe('/users');
      expect(error.requiredPermissions).toEqual(['User.Read.All', 'Directory.Read.All']);
    });
  });

  describe('AzureConfigurationError', () => {
    it('should create configuration error', () => {
      const error = new AzureConfigurationError('Missing tenant ID', 'tenantId');

      expect(error).toBeInstanceOf(AzureError);
      expect(error.name).toBe('AzureConfigurationError');
      expect(error.configKey).toBe('tenantId');
    });
  });

  describe('AzureTokenExpiredError', () => {
    it('should create token expired error', () => {
      const expiresAt = new Date('2026-01-13T00:00:00Z');
      const error = new AzureTokenExpiredError('Token expired', expiresAt);

      expect(error).toBeInstanceOf(AzureError);
      expect(error.name).toBe('AzureTokenExpiredError');
      expect(error.expiresAt).toEqual(expiresAt);
    });
  });

  describe('isRetryableError', () => {
    it('should identify rate limit errors as retryable', () => {
      const error = new AzureRateLimitError('Rate limited', '/users', 60);
      expect(isRetryableError(error)).toBe(true);
    });

    it('should identify timeout errors as retryable', () => {
      const error = new AzureTimeoutError('Timeout', 'GET /users', 30000);
      expect(isRetryableError(error)).toBe(true);
    });

    it('should identify 429 API errors as retryable', () => {
      const error = new AzureAPIError('Too many requests', '/users', 429);
      expect(isRetryableError(error)).toBe(true);
    });

    it('should identify 500 API errors as retryable', () => {
      const error = new AzureAPIError('Server error', '/users', 500);
      expect(isRetryableError(error)).toBe(true);
    });

    it('should identify 503 API errors as retryable', () => {
      const error = new AzureAPIError('Service unavailable', '/users', 503);
      expect(isRetryableError(error)).toBe(true);
    });

    it('should NOT identify 404 API errors as retryable', () => {
      const error = new AzureAPIError('Not found', '/users', 404);
      expect(isRetryableError(error)).toBe(false);
    });

    it('should NOT identify authentication errors as retryable', () => {
      const error = new AzureAuthenticationError('Auth failed', 'tenant', 'client');
      expect(isRetryableError(error)).toBe(false);
    });

    it('should NOT identify permission errors as retryable', () => {
      const error = new AzurePermissionError('No access', '/users', ['User.Read.All']);
      expect(isRetryableError(error)).toBe(false);
    });

    it('should identify network errors as retryable', () => {
      const error = new Error('Network error') as Error & { code: string };
      error.code = 'ECONNREFUSED';
      expect(isRetryableError(error)).toBe(true);
    });

    it('should identify ETIMEDOUT errors as retryable', () => {
      const error = new Error('Connection timed out') as Error & { code: string };
      error.code = 'ETIMEDOUT';
      expect(isRetryableError(error)).toBe(true);
    });

    it('should NOT identify unknown errors as retryable', () => {
      const error = new Error('Unknown error');
      expect(isRetryableError(error)).toBe(false);
    });
  });
});
