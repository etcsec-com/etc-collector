/**
 * Azure Error Types
 *
 * Custom error classes for Microsoft Graph / Azure AD operations.
 * Provides specific error types for different failure scenarios.
 *
 * Task 2: Create Error Types for Azure Operations (Story 1.6)
 */

/**
 * Base Azure Error
 *
 * Base class for all Azure/Microsoft Graph-related errors.
 */
export class AzureError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'AzureError';
    Object.setPrototypeOf(this, AzureError.prototype);
  }
}

/**
 * Azure Authentication Error
 *
 * Thrown when OAuth 2.0 authentication fails.
 */
export class AzureAuthenticationError extends AzureError {
  public readonly tenantId: string;
  public readonly clientId: string;
  public override readonly cause?: Error;

  constructor(message: string, tenantId: string, clientId: string, cause?: Error) {
    super(message);
    this.name = 'AzureAuthenticationError';
    this.tenantId = tenantId;
    this.clientId = clientId;
    this.cause = cause;
    Object.setPrototypeOf(this, AzureAuthenticationError.prototype);
  }
}

/**
 * Azure API Error
 *
 * Thrown when Microsoft Graph API request fails.
 */
export class AzureAPIError extends AzureError {
  public readonly statusCode?: number;
  public readonly endpoint: string;
  public override readonly cause?: Error;

  constructor(message: string, endpoint: string, statusCode?: number, cause?: Error) {
    super(message);
    this.name = 'AzureAPIError';
    this.endpoint = endpoint;
    this.statusCode = statusCode;
    this.cause = cause;
    Object.setPrototypeOf(this, AzureAPIError.prototype);
  }
}

/**
 * Azure Rate Limit Error
 *
 * Thrown when Graph API rate limit (429) is exceeded.
 */
export class AzureRateLimitError extends AzureError {
  public readonly retryAfter: number; // seconds
  public readonly endpoint: string;

  constructor(message: string, endpoint: string, retryAfter: number) {
    super(message);
    this.name = 'AzureRateLimitError';
    this.endpoint = endpoint;
    this.retryAfter = retryAfter;
    Object.setPrototypeOf(this, AzureRateLimitError.prototype);
  }
}

/**
 * Azure Timeout Error
 *
 * Thrown when Graph API request times out.
 */
export class AzureTimeoutError extends AzureError {
  public readonly operation: string;
  public readonly timeoutMs: number;

  constructor(message: string, operation: string, timeoutMs: number) {
    super(message);
    this.name = 'AzureTimeoutError';
    this.operation = operation;
    this.timeoutMs = timeoutMs;
    Object.setPrototypeOf(this, AzureTimeoutError.prototype);
  }
}

/**
 * Azure Permission Error
 *
 * Thrown when application doesn't have required permissions.
 */
export class AzurePermissionError extends AzureError {
  public readonly requiredPermissions: string[];
  public readonly endpoint: string;

  constructor(message: string, endpoint: string, requiredPermissions: string[]) {
    super(message);
    this.name = 'AzurePermissionError';
    this.endpoint = endpoint;
    this.requiredPermissions = requiredPermissions;
    Object.setPrototypeOf(this, AzurePermissionError.prototype);
  }
}

/**
 * Azure Configuration Error
 *
 * Thrown when Azure configuration is invalid or missing.
 */
export class AzureConfigurationError extends AzureError {
  public readonly configKey: string;

  constructor(message: string, configKey: string) {
    super(message);
    this.name = 'AzureConfigurationError';
    this.configKey = configKey;
    Object.setPrototypeOf(this, AzureConfigurationError.prototype);
  }
}

/**
 * Azure Token Expired Error
 *
 * Thrown when access token has expired and needs refresh.
 */
export class AzureTokenExpiredError extends AzureError {
  public readonly expiresAt: Date;

  constructor(message: string, expiresAt: Date) {
    super(message);
    this.name = 'AzureTokenExpiredError';
    this.expiresAt = expiresAt;
    Object.setPrototypeOf(this, AzureTokenExpiredError.prototype);
  }
}

/**
 * Check if an error is retryable
 *
 * Determines if an Azure operation should be retried based on error type.
 * Rate limit errors (429) and transient network errors are retryable.
 *
 * @param error - The error to check
 * @returns True if the error is retryable
 */
export function isRetryableError(error: Error): boolean {
  // Rate limit errors are retryable with delay
  if (error instanceof AzureRateLimitError) {
    return true;
  }

  // Timeout errors are retryable
  if (error instanceof AzureTimeoutError) {
    return true;
  }

  // API errors with certain status codes are retryable
  if (error instanceof AzureAPIError) {
    const retryableStatusCodes = [429, 500, 502, 503, 504];
    return error.statusCode ? retryableStatusCodes.includes(error.statusCode) : false;
  }

  // Network errors (ECONNREFUSED, ETIMEDOUT, etc.) are retryable
  if ('code' in error) {
    const networkErrorCodes = [
      'ECONNREFUSED',
      'ECONNRESET',
      'ETIMEDOUT',
      'ENOTFOUND',
      'ENETUNREACH',
      'EHOSTUNREACH',
    ];
    return networkErrorCodes.includes((error as { code: string }).code);
  }

  return false;
}
