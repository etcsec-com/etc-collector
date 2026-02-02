/**
 * Azure Retry Logic Unit Tests
 *
 * Tests for retry logic with exponential backoff and rate limit handling.
 */

import {
  retryWithBackoff,
  calculateDelay,
  AZURE_RETRY_CONFIGS,
  RetryOptions,
} from '../../../../src/providers/azure/azure-retry';
import {
  AzureRateLimitError,
  AzureTimeoutError,
  AzureAuthenticationError,
} from '../../../../src/providers/azure/azure-errors';

describe('Azure Retry Logic', () => {
  describe('calculateDelay', () => {
    const options: Required<RetryOptions> = {
      maxAttempts: 3,
      initialDelay: 1000,
      maxDelay: 30000,
      backoffMultiplier: 2,
      jitterPercent: 0, // No jitter for predictable testing
      onRetry: () => {},
    };

    it('should calculate exponential backoff delays', () => {
      const delay0 = calculateDelay(0, options);
      const delay1 = calculateDelay(1, options);
      const delay2 = calculateDelay(2, options);

      expect(delay0).toBe(1000); // 1000 * 2^0 = 1000
      expect(delay1).toBe(2000); // 1000 * 2^1 = 2000
      expect(delay2).toBe(4000); // 1000 * 2^2 = 4000
    });

    it('should cap delay at maxDelay', () => {
      const delay5 = calculateDelay(5, options); // 1000 * 2^5 = 32000
      expect(delay5).toBe(30000); // Capped at maxDelay
    });

    it('should add jitter when enabled', () => {
      const optionsWithJitter: Required<RetryOptions> = {
        ...options,
        jitterPercent: 10, // 10% jitter
      };

      const delays = Array.from({ length: 10 }, () => calculateDelay(0, optionsWithJitter));

      // All delays should be different (with high probability)
      const uniqueDelays = new Set(delays);
      expect(uniqueDelays.size).toBeGreaterThan(1);

      // All delays should be within range [1000, 1100]
      delays.forEach((delay) => {
        expect(delay).toBeGreaterThanOrEqual(1000);
        expect(delay).toBeLessThanOrEqual(1100);
      });
    });
  });

  describe('retryWithBackoff', () => {
    it('should succeed on first attempt', async () => {
      const operation = jest.fn().mockResolvedValue('success');

      const result = await retryWithBackoff(operation);

      expect(result).toBe('success');
      expect(operation).toHaveBeenCalledTimes(1);
    });

    it('should retry on retryable error and eventually succeed', async () => {
      const operation = jest
        .fn()
        .mockRejectedValueOnce(new AzureTimeoutError('Timeout', 'GET /users', 30000))
        .mockResolvedValue('success');

      const result = await retryWithBackoff(operation, {
        maxAttempts: 3,
        initialDelay: 10,
        maxDelay: 100,
      });

      expect(result).toBe('success');
      expect(operation).toHaveBeenCalledTimes(2);
    });

    it('should throw error if all retries fail', async () => {
      const error = new AzureTimeoutError('Timeout', 'GET /users', 30000);
      const operation = jest.fn().mockRejectedValue(error);

      await expect(
        retryWithBackoff(operation, {
          maxAttempts: 3,
          initialDelay: 10,
          maxDelay: 100,
        })
      ).rejects.toThrow(error);

      expect(operation).toHaveBeenCalledTimes(3);
    });

    it('should NOT retry non-retryable errors', async () => {
      const error = new AzureAuthenticationError('Auth failed', 'tenant', 'client');
      const operation = jest.fn().mockRejectedValue(error);

      await expect(
        retryWithBackoff(operation, {
          maxAttempts: 3,
          initialDelay: 10,
        })
      ).rejects.toThrow(error);

      expect(operation).toHaveBeenCalledTimes(1); // Should not retry
    });

    it('should use retry-after for rate limit errors', async () => {
      const rateLimitError = new AzureRateLimitError('Rate limited', '/users', 2); // 2 seconds
      const operation = jest
        .fn()
        .mockRejectedValueOnce(rateLimitError)
        .mockResolvedValue('success');

      const startTime = Date.now();
      const result = await retryWithBackoff(operation, {
        maxAttempts: 3,
        initialDelay: 10,
        maxDelay: 5000,
      });
      const elapsed = Date.now() - startTime;

      expect(result).toBe('success');
      expect(operation).toHaveBeenCalledTimes(2);
      // Should have waited ~2 seconds (retry-after value)
      expect(elapsed).toBeGreaterThanOrEqual(1900);
      expect(elapsed).toBeLessThan(3000);
    });

    it('should call onRetry callback', async () => {
      const onRetry = jest.fn();
      const error = new AzureTimeoutError('Timeout', 'GET /users', 30000);
      const operation = jest
        .fn()
        .mockRejectedValueOnce(error)
        .mockResolvedValue('success');

      await retryWithBackoff(operation, {
        maxAttempts: 3,
        initialDelay: 10,
        maxDelay: 100,
        onRetry,
      });

      expect(onRetry).toHaveBeenCalledTimes(1);
      expect(onRetry).toHaveBeenCalledWith(error, 0, expect.any(Number));
    });

    it('should handle multiple retries with exponential backoff', async () => {
      const delays: number[] = [];
      const onRetry = jest.fn((_error, _attempt, delay) => {
        delays.push(delay);
      });

      const operation = jest
        .fn()
        .mockRejectedValueOnce(new AzureTimeoutError('Timeout 1', 'GET /users', 30000))
        .mockRejectedValueOnce(new AzureTimeoutError('Timeout 2', 'GET /users', 30000))
        .mockResolvedValue('success');

      await retryWithBackoff(operation, {
        maxAttempts: 3,
        initialDelay: 100,
        maxDelay: 1000,
        backoffMultiplier: 2,
        jitterPercent: 0,
        onRetry,
      });

      expect(delays.length).toBe(2);
      expect(delays[0]).toBe(100); // 100 * 2^0 = 100
      expect(delays[1]).toBe(200); // 100 * 2^1 = 200
    });

    it('should respect maxDelay cap', async () => {
      const delays: number[] = [];
      const onRetry = jest.fn((_error, _attempt, delay) => {
        delays.push(delay);
      });

      const operation = jest
        .fn()
        .mockRejectedValueOnce(new AzureTimeoutError('Timeout 1', 'GET /users', 30000))
        .mockRejectedValueOnce(new AzureTimeoutError('Timeout 2', 'GET /users', 30000))
        .mockResolvedValue('success');

      await retryWithBackoff(operation, {
        maxAttempts: 3,
        initialDelay: 1000,
        maxDelay: 1500, // Cap at 1500ms
        backoffMultiplier: 3,
        jitterPercent: 0,
        onRetry,
      });

      expect(delays[0]).toBe(1000); // 1000 * 3^0 = 1000
      expect(delays[1]).toBe(1500); // 1000 * 3^1 = 3000, capped at 1500
    });
  });

  describe('AZURE_RETRY_CONFIGS', () => {
    it('should have default config', () => {
      expect(AZURE_RETRY_CONFIGS.default).toEqual({
        maxAttempts: 3,
        initialDelay: 1000,
        maxDelay: 30000,
        backoffMultiplier: 2,
        jitterPercent: 10,
      });
    });

    it('should have aggressive config', () => {
      expect(AZURE_RETRY_CONFIGS.aggressive).toEqual({
        maxAttempts: 5,
        initialDelay: 500,
        maxDelay: 15000,
        backoffMultiplier: 1.5,
        jitterPercent: 15,
      });
    });

    it('should have conservative config', () => {
      expect(AZURE_RETRY_CONFIGS.conservative).toEqual({
        maxAttempts: 2,
        initialDelay: 2000,
        maxDelay: 60000,
        backoffMultiplier: 3,
        jitterPercent: 5,
      });
    });

    it('should have rate limit config', () => {
      expect(AZURE_RETRY_CONFIGS.rateLimit).toEqual({
        maxAttempts: 3,
        initialDelay: 60000,
        maxDelay: 300000,
        backoffMultiplier: 1,
        jitterPercent: 0,
      });
    });
  });
});
