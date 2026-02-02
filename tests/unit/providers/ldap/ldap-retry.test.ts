import {
  retryWithBackoff,
  retryable,
  isRetryableError,
  LDAP_RETRY_OPTIONS,
} from '../../../../src/providers/ldap/ldap-retry';

/**
 * Unit Tests for LDAP Retry Logic
 * Task 8: Write Unit Tests for LDAP Provider (Story 1.5)
 */

// Mock logger to avoid console output during tests
jest.mock('../../../../src/utils/logger', () => ({
  logger: {
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
    debug: jest.fn(),
  },
}));

describe('LDAP Retry Logic', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('isRetryableError', () => {
    it('should identify ECONNREFUSED as retryable', () => {
      const error = new Error('Connection refused') as Error & { code: string };
      error.code = 'ECONNREFUSED';

      expect(isRetryableError(error)).toBe(true);
    });

    it('should identify ECONNRESET as retryable', () => {
      const error = new Error('Connection reset') as Error & { code: string };
      error.code = 'ECONNRESET';

      expect(isRetryableError(error)).toBe(true);
    });

    it('should identify ETIMEDOUT as retryable', () => {
      const error = new Error('Timeout') as Error & { code: string };
      error.code = 'ETIMEDOUT';

      expect(isRetryableError(error)).toBe(true);
    });

    it('should identify timeout message as retryable', () => {
      const error = new Error('Operation timed out');

      expect(isRetryableError(error)).toBe(true);
    });

    it('should identify connection errors as retryable', () => {
      const error = new Error('Connection error occurred');

      expect(isRetryableError(error)).toBe(true);
    });

    it('should identify network errors as retryable', () => {
      const error = new Error('Network is unavailable');

      expect(isRetryableError(error)).toBe(true);
    });

    it('should NOT identify authentication errors as retryable', () => {
      const error = new Error('Invalid credentials');

      expect(isRetryableError(error)).toBe(false);
    });

    it('should NOT identify bind failures as retryable', () => {
      const error = new Error('Bind failed: invalid DN');

      expect(isRetryableError(error)).toBe(false);
    });

    it('should NOT identify authentication failed as retryable', () => {
      const error = new Error('Authentication failed');

      expect(isRetryableError(error)).toBe(false);
    });
  });

  describe('retryWithBackoff', () => {
    it('should succeed on first attempt', async () => {
      const operation = jest.fn().mockResolvedValue('success');

      const result = await retryWithBackoff(operation, { maxAttempts: 3 });

      expect(result).toBe('success');
      expect(operation).toHaveBeenCalledTimes(1);
    });

    it('should retry on failure and eventually succeed', async () => {
      const operation = jest
        .fn()
        .mockRejectedValueOnce(new Error('Temporary failure'))
        .mockRejectedValueOnce(new Error('Another failure'))
        .mockResolvedValue('success');

      const result = await retryWithBackoff(operation, {
        maxAttempts: 3,
        initialDelay: 10,
      });

      expect(result).toBe('success');
      expect(operation).toHaveBeenCalledTimes(3);
    });

    it('should throw error after max attempts', async () => {
      const operation = jest.fn().mockRejectedValue(new Error('Persistent failure'));

      await expect(
        retryWithBackoff(operation, {
          maxAttempts: 3,
          initialDelay: 10,
        })
      ).rejects.toThrow('Persistent failure');

      expect(operation).toHaveBeenCalledTimes(3);
    });

    it('should not retry if shouldRetry returns false', async () => {
      const operation = jest.fn().mockRejectedValue(new Error('Auth failure'));

      await expect(
        retryWithBackoff(operation, {
          maxAttempts: 3,
          initialDelay: 10,
          shouldRetry: () => false,
        })
      ).rejects.toThrow('Auth failure');

      expect(operation).toHaveBeenCalledTimes(1);
    });

    it('should call onRetry callback before each retry', async () => {
      const operation = jest
        .fn()
        .mockRejectedValueOnce(new Error('Failure 1'))
        .mockResolvedValue('success');

      const onRetry = jest.fn();

      await retryWithBackoff(operation, {
        maxAttempts: 3,
        initialDelay: 10,
        onRetry,
      });

      expect(onRetry).toHaveBeenCalledTimes(1);
      expect(onRetry).toHaveBeenCalledWith(
        expect.objectContaining({ message: 'Failure 1' }),
        0,
        expect.any(Number)
      );
    });

    it('should apply exponential backoff', async () => {
      const operation = jest
        .fn()
        .mockRejectedValueOnce(new Error('Failure 1'))
        .mockRejectedValueOnce(new Error('Failure 2'))
        .mockResolvedValue('success');

      const delays: number[] = [];
      const onRetry = jest.fn((_error, _attempt, delay) => {
        delays.push(delay);
      });

      const startTime = Date.now();

      await retryWithBackoff(operation, {
        maxAttempts: 3,
        initialDelay: 100,
        backoffMultiplier: 2,
        jitterFactor: 0,
        onRetry,
      });

      const elapsedTime = Date.now() - startTime;

      // First delay should be ~100ms, second should be ~200ms
      // Total should be at least 300ms
      expect(elapsedTime).toBeGreaterThanOrEqual(250);
      expect(delays[0]).toBeGreaterThanOrEqual(90);
      expect(delays[1]).toBeGreaterThanOrEqual(180);
    });

    it(
      'should respect maxDelay cap',
      async () => {
        const operation = jest.fn().mockRejectedValue(new Error('Failure'));

        const delays: number[] = [];
        const onRetry = jest.fn((_error, _attempt, delay) => {
          delays.push(delay);
        });

        try {
          await retryWithBackoff(operation, {
            maxAttempts: 5,
            initialDelay: 1000,
            maxDelay: 2000,
            backoffMultiplier: 3,
            jitterFactor: 0,
            onRetry,
          });
        } catch (error) {
          // Expected to fail
        }

        // All delays should be capped at maxDelay
        delays.forEach((delay) => {
          expect(delay).toBeLessThanOrEqual(2000);
        });
      },
      10000
    ); // 10 second timeout

    it('should add jitter to delays', async () => {
      const operation = jest
        .fn()
        .mockRejectedValueOnce(new Error('Failure 1'))
        .mockRejectedValueOnce(new Error('Failure 2'))
        .mockResolvedValue('success');

      const delays: number[] = [];
      const onRetry = jest.fn((_error, _attempt, delay) => {
        delays.push(delay);
      });

      await retryWithBackoff(operation, {
        maxAttempts: 3,
        initialDelay: 1000,
        backoffMultiplier: 1,
        jitterFactor: 0.5, // 50% jitter
        onRetry,
      });

      // With jitter, delays should vary around 1000ms
      // Could be between 500ms and 1500ms
      delays.forEach((delay) => {
        expect(delay).toBeGreaterThanOrEqual(400);
        expect(delay).toBeLessThanOrEqual(1600);
      });
    });

    it('should handle non-Error objects', async () => {
      const operation = jest.fn().mockRejectedValue('String error');

      await expect(
        retryWithBackoff(operation, {
          maxAttempts: 2,
          initialDelay: 10,
        })
      ).rejects.toThrow('String error');

      expect(operation).toHaveBeenCalledTimes(2);
    });
  });

  describe('retryable', () => {
    it('should create retryable function that succeeds', async () => {
      const originalFn = jest.fn((x: number) => Promise.resolve(x * 2));
      const retryableFn = retryable(originalFn, { maxAttempts: 3 });

      const result = await retryableFn(5);

      expect(result).toBe(10);
      expect(originalFn).toHaveBeenCalledWith(5);
      expect(originalFn).toHaveBeenCalledTimes(1);
    });

    it('should create retryable function that retries on failure', async () => {
      const originalFn = jest
        .fn()
        .mockRejectedValueOnce(new Error('Failure'))
        .mockResolvedValue('success');

      const retryableFn = retryable(originalFn, {
        maxAttempts: 3,
        initialDelay: 10,
      });

      const result = await retryableFn();

      expect(result).toBe('success');
      expect(originalFn).toHaveBeenCalledTimes(2);
    });

    it('should pass arguments to retried function', async () => {
      const originalFn = jest.fn((a: number, b: string) =>
        Promise.resolve(`${a}-${b}`)
      );

      const retryableFn = retryable(originalFn);

      const result = await retryableFn(42, 'test');

      expect(result).toBe('42-test');
      expect(originalFn).toHaveBeenCalledWith(42, 'test');
    });
  });

  describe('LDAP_RETRY_OPTIONS', () => {
    it('should have correct default values', () => {
      expect(LDAP_RETRY_OPTIONS.maxAttempts).toBe(3);
      expect(LDAP_RETRY_OPTIONS.initialDelay).toBe(1000);
      expect(LDAP_RETRY_OPTIONS.maxDelay).toBe(10000);
      expect(LDAP_RETRY_OPTIONS.backoffMultiplier).toBe(2);
      expect(LDAP_RETRY_OPTIONS.jitterFactor).toBe(0.1);
    });

    it('should use isRetryableError as shouldRetry', () => {
      const retryableErr = new Error('timeout') as Error;
      const nonRetryableErr = new Error('invalid credentials');

      expect(LDAP_RETRY_OPTIONS.shouldRetry!(retryableErr, 0)).toBe(true);
      expect(LDAP_RETRY_OPTIONS.shouldRetry!(nonRetryableErr, 0)).toBe(false);
    });

    it('should have onRetry callback', () => {
      expect(LDAP_RETRY_OPTIONS.onRetry).toBeDefined();
      expect(typeof LDAP_RETRY_OPTIONS.onRetry).toBe('function');
    });
  });

  describe('Integration test with realistic scenario', () => {
    it('should handle transient network failure followed by success', async () => {
      // Simulate a flaky network connection
      let attemptCount = 0;
      const flakyOperation = async () => {
        attemptCount++;
        if (attemptCount < 3) {
          const error = new Error('Network timeout') as Error & { code: string };
          error.code = 'ETIMEDOUT';
          throw error;
        }
        return 'Connected successfully';
      };

      const result = await retryWithBackoff(flakyOperation, {
        maxAttempts: 3,
        initialDelay: 10,
        shouldRetry: isRetryableError,
      });

      expect(result).toBe('Connected successfully');
      expect(attemptCount).toBe(3);
    });

    it('should immediately fail on authentication error', async () => {
      const operation = async () => {
        throw new Error('Invalid credentials');
      };

      const startTime = Date.now();

      await expect(
        retryWithBackoff(operation, {
          maxAttempts: 5,
          initialDelay: 100,
          shouldRetry: isRetryableError,
        })
      ).rejects.toThrow('Invalid credentials');

      const elapsedTime = Date.now() - startTime;

      // Should fail immediately without retries (< 50ms)
      expect(elapsedTime).toBeLessThan(50);
    });
  });
});
