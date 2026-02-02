/**
 * JWT Authentication Errors
 *
 * Custom error classes for token validation and authentication failures.
 */

export class TokenExpiredError extends Error {
  constructor(message = 'Token has expired') {
    super(message);
    this.name = 'TokenExpiredError';
  }
}

export class TokenRevokedError extends Error {
  constructor(message = 'Token has been revoked') {
    super(message);
    this.name = 'TokenRevokedError';
  }
}

export class UsageLimitExceededError extends Error {
  constructor(message = 'Token usage limit exceeded') {
    super(message);
    this.name = 'UsageLimitExceededError';
  }
}

export class TokenNotFoundError extends Error {
  constructor(message = 'Token not found in database') {
    super(message);
    this.name = 'TokenNotFoundError';
  }
}

export class InvalidSignatureError extends Error {
  constructor(message = 'Invalid token signature') {
    super(message);
    this.name = 'InvalidSignatureError';
  }
}

export class InvalidTokenError extends Error {
  constructor(message = 'Invalid token') {
    super(message);
    this.name = 'InvalidTokenError';
  }
}
