import { logger } from '../../utils/logger';

/**
 * LDAP Retry Logic
 *
 * Provides retry functionality with exponential backoff for LDAP operations.
 * Handles transient network errors and connection failures.
 *
 * Task 6: Implement Retry Logic with Exponential Backoff (Story 1.5)
 */

/**
 * Retry options
 */
export interface RetryOptions {
  /**
   * Maximum number of retry attempts
   * @default 3
   */
  maxAttempts?: number;

  /**
   * Initial delay in milliseconds before first retry
   * @default 1000
   */
  initialDelay?: number;

  /**
   * Maximum delay in milliseconds between retries
   * @default 30000
   */
  maxDelay?: number;

  /**
   * Backoff multiplier (exponential growth factor)
   * @default 2
   */
  backoffMultiplier?: number;

  /**
   * Jitter factor (randomization to prevent thundering herd)
   * @default 0.1 (10% jitter)
   */
  jitterFactor?: number;

  /**
   * Predicate to determine if error is retryable
   * @default all errors are retryable
   */
  shouldRetry?: (error: Error, attempt: number) => boolean;

  /**
   * Callback invoked before each retry attempt
   */
  onRetry?: (error: Error, attempt: number, delay: number) => void;
}

/**
 * Default retry options
 */
const DEFAULT_RETRY_OPTIONS: Required<RetryOptions> = {
  maxAttempts: 3,
  initialDelay: 1000,
  maxDelay: 30000,
  backoffMultiplier: 2,
  jitterFactor: 0.1,
  shouldRetry: () => true,
  onRetry: () => {},
};

/**
 * Common retryable LDAP errors
 */
const RETRYABLE_ERROR_CODES = [
  'ECONNREFUSED',
  'ECONNRESET',
  'ETIMEDOUT',
  'ENOTFOUND',
  'ENETUNREACH',
  'EHOSTUNREACH',
];

/**
 * Check if error is retryable
 *
 * Determines if an error represents a transient failure that may succeed on retry.
 */
export function isRetryableError(error: Error): boolean {
  // Check error code for network errors
  if ('code' in error && typeof error.code === 'string') {
    if (RETRYABLE_ERROR_CODES.includes(error.code)) {
      return true;
    }
  }

  // Check error message for common LDAP errors
  const message = error.message.toLowerCase();
  if (
    message.includes('timeout') ||
    message.includes('timed out') ||
    message.includes('connection') ||
    message.includes('network') ||
    message.includes('unavailable')
  ) {
    return true;
  }

  // Authentication errors are NOT retryable
  if (
    message.includes('invalid credentials') ||
    message.includes('authentication failed') ||
    message.includes('bind failed')
  ) {
    return false;
  }

  return false;
}

/**
 * Calculate delay with exponential backoff and jitter
 *
 * @param attempt - Current attempt number (0-indexed)
 * @param options - Retry options
 * @returns Delay in milliseconds
 */
function calculateDelay(attempt: number, options: Required<RetryOptions>): number {
  // Calculate exponential backoff
  const exponentialDelay = options.initialDelay * Math.pow(options.backoffMultiplier, attempt);

  // Apply maximum delay cap
  const cappedDelay = Math.min(exponentialDelay, options.maxDelay);

  // Add jitter to prevent thundering herd
  const jitter = cappedDelay * options.jitterFactor * (Math.random() * 2 - 1);
  const delayWithJitter = cappedDelay + jitter;

  // Ensure non-negative delay
  return Math.max(0, delayWithJitter);
}

/**
 * Sleep for specified milliseconds
 */
function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Retry an async operation with exponential backoff
 *
 * @param operation - Async function to retry
 * @param options - Retry options
 * @returns Result of the operation
 *
 * @throws Last error if all retry attempts fail
 *
 * @example
 * ```typescript
 * const result = await retryWithBackoff(
 *   async () => await ldapClient.search(baseDN, filter),
 *   {
 *     maxAttempts: 3,
 *     initialDelay: 1000,
 *     shouldRetry: isRetryableError,
 *   }
 * );
 * ```
 */
export async function retryWithBackoff<T>(
  operation: () => Promise<T>,
  options: RetryOptions = {}
): Promise<T> {
  // Merge with defaults
  const opts: Required<RetryOptions> = {
    ...DEFAULT_RETRY_OPTIONS,
    ...options,
    shouldRetry: options.shouldRetry || DEFAULT_RETRY_OPTIONS.shouldRetry,
    onRetry: options.onRetry || DEFAULT_RETRY_OPTIONS.onRetry,
  };

  let lastError: Error | undefined;
  let attempt = 0;

  while (attempt < opts.maxAttempts) {
    try {
      // Attempt the operation
      return await operation();
    } catch (error) {
      lastError = error instanceof Error ? error : new Error(String(error));

      // Check if we should retry
      const isLastAttempt = attempt === opts.maxAttempts - 1;
      const shouldRetry = opts.shouldRetry(lastError, attempt);

      if (isLastAttempt || !shouldRetry) {
        // No more retries or error not retryable
        throw lastError;
      }

      // Calculate delay for next retry
      const delay = calculateDelay(attempt, opts);

      // Log retry attempt
      logger.warn(
        `Operation failed (attempt ${attempt + 1}/${opts.maxAttempts}): ${lastError.message}. ` +
          `Retrying in ${Math.round(delay)}ms...`
      );

      // Invoke retry callback
      opts.onRetry(lastError, attempt, delay);

      // Wait before retrying
      await sleep(delay);

      attempt++;
    }
  }

  // Should never reach here, but TypeScript requires it
  throw lastError || new Error('Operation failed after all retries');
}

/**
 * Create a retryable version of an async function
 *
 * Returns a new function that wraps the original with retry logic.
 *
 * @param fn - Async function to wrap
 * @param options - Retry options
 * @returns Wrapped function with retry logic
 *
 * @example
 * ```typescript
 * const retryableSearch = retryable(
 *   (baseDN: string, filter: string) => client.search(baseDN, filter),
 *   { maxAttempts: 3, shouldRetry: isRetryableError }
 * );
 *
 * const results = await retryableSearch('dc=example,dc=com', '(uid=john)');
 * ```
 */
export function retryable<TArgs extends unknown[], TReturn>(
  fn: (...args: TArgs) => Promise<TReturn>,
  options: RetryOptions = {}
): (...args: TArgs) => Promise<TReturn> {
  return async (...args: TArgs): Promise<TReturn> => {
    return retryWithBackoff(() => fn(...args), options);
  };
}

/**
 * Retry options for LDAP operations
 *
 * Preconfigured retry options suitable for LDAP operations.
 */
export const LDAP_RETRY_OPTIONS: RetryOptions = {
  maxAttempts: 3,
  initialDelay: 1000,
  maxDelay: 10000,
  backoffMultiplier: 2,
  jitterFactor: 0.1,
  shouldRetry: isRetryableError,
  onRetry: (error, attempt, delay) => {
    logger.debug(`LDAP operation retry: attempt=${attempt}, error=${error.message}, delay=${delay}ms`);
  },
};
