/**
 * Azure Retry Logic
 *
 * Provides retry functionality for Azure/Microsoft Graph API operations.
 * Implements exponential backoff with jitter and special handling for rate limits (429).
 *
 * Task 5: Add retry logic with exponential backoff (Story 1.6)
 */

import { AzureRateLimitError, isRetryableError } from './azure-errors';

/**
 * Retry options
 */
export interface RetryOptions {
  maxAttempts?: number; // default: 3
  initialDelay?: number; // milliseconds, default: 1000
  maxDelay?: number; // milliseconds, default: 30000
  backoffMultiplier?: number; // default: 2
  jitterPercent?: number; // 0-100, default: 10
  onRetry?: (error: Error, attempt: number, delay: number) => void;
}

/**
 * Sleep for specified milliseconds
 *
 * @param ms - Milliseconds to sleep
 */
function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Calculate delay with exponential backoff and jitter
 *
 * @param attempt - Current attempt number (0-based)
 * @param options - Retry options
 * @returns Delay in milliseconds
 */
export function calculateDelay(attempt: number, options: Required<RetryOptions>): number {
  // Exponential backoff: initialDelay * (multiplier ^ attempt)
  const exponentialDelay = options.initialDelay * Math.pow(options.backoffMultiplier, attempt);

  // Cap at maxDelay
  const cappedDelay = Math.min(exponentialDelay, options.maxDelay);

  // Add jitter to prevent thundering herd
  // Jitter is random value between [0, jitterPercent% of delay]
  const jitterAmount = cappedDelay * (options.jitterPercent / 100);
  const jitter = Math.random() * jitterAmount;

  return Math.round(cappedDelay + jitter);
}

/**
 * Retry an async operation with exponential backoff
 *
 * @param operation - Async operation to retry
 * @param options - Retry options
 * @returns Result of the operation
 * @throws Last error if all retries fail
 */
export async function retryWithBackoff<T>(
  operation: () => Promise<T>,
  options: RetryOptions = {}
): Promise<T> {
  const opts: Required<RetryOptions> = {
    maxAttempts: options.maxAttempts ?? 3,
    initialDelay: options.initialDelay ?? 1000,
    maxDelay: options.maxDelay ?? 30000,
    backoffMultiplier: options.backoffMultiplier ?? 2,
    jitterPercent: options.jitterPercent ?? 10,
    onRetry: options.onRetry ?? (() => {}),
  };

  let attempt = 0;
  let lastError: Error | undefined;

  while (attempt < opts.maxAttempts) {
    try {
      return await operation();
    } catch (error) {
      lastError = error instanceof Error ? error : new Error(String(error));

      const isLastAttempt = attempt === opts.maxAttempts - 1;

      // Don't retry if it's the last attempt
      if (isLastAttempt) {
        throw lastError;
      }

      // Check if error is retryable
      if (!isRetryableError(lastError)) {
        throw lastError;
      }

      // For rate limit errors, use the retry-after value
      let delay: number;
      if (lastError instanceof AzureRateLimitError) {
        // Use the retry-after value from the error (in seconds)
        delay = lastError.retryAfter * 1000; // convert to ms
      } else {
        // Calculate delay with exponential backoff
        delay = calculateDelay(attempt, opts);
      }

      // Call retry callback
      opts.onRetry(lastError, attempt, delay);

      // Wait before retrying
      await sleep(delay);

      attempt++;
    }
  }

  // This should never happen, but TypeScript doesn't know that
  throw lastError || new Error('Retry failed with unknown error');
}

/**
 * Retry configuration for different scenarios
 */
export const AZURE_RETRY_CONFIGS = {
  /**
   * Default retry config for most operations
   */
  default: {
    maxAttempts: 3,
    initialDelay: 1000, // 1 second
    maxDelay: 30000, // 30 seconds
    backoffMultiplier: 2,
    jitterPercent: 10,
  },

  /**
   * Aggressive retry config for operations that are likely to succeed quickly
   */
  aggressive: {
    maxAttempts: 5,
    initialDelay: 500, // 0.5 seconds
    maxDelay: 15000, // 15 seconds
    backoffMultiplier: 1.5,
    jitterPercent: 15,
  },

  /**
   * Conservative retry config for expensive operations
   */
  conservative: {
    maxAttempts: 2,
    initialDelay: 2000, // 2 seconds
    maxDelay: 60000, // 60 seconds
    backoffMultiplier: 3,
    jitterPercent: 5,
  },

  /**
   * Rate limit retry config - respects rate limit headers
   */
  rateLimit: {
    maxAttempts: 3,
    initialDelay: 60000, // 60 seconds (default if no retry-after header)
    maxDelay: 300000, // 5 minutes
    backoffMultiplier: 1, // Don't use exponential backoff for rate limits
    jitterPercent: 0, // No jitter for rate limits (use exact retry-after)
  },
} as const;
