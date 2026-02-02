/**
 * Custom Error Classes
 */

export class BaseError extends Error {
  constructor(
    message: string,
    public statusCode: number = 500,
    public isOperational: boolean = true
  ) {
    super(message);
    this.name = this.constructor.name;
    Error.captureStackTrace(this, this.constructor);
  }
}

export class AuthenticationError extends BaseError {
  constructor(message = 'Authentication failed') {
    super(message, 401);
  }
}

export class AuthorizationError extends BaseError {
  constructor(message = 'Insufficient permissions') {
    super(message, 403);
  }
}

export class ValidationError extends BaseError {
  constructor(message = 'Validation failed') {
    super(message, 400);
  }
}

export class NotFoundError extends BaseError {
  constructor(message = 'Resource not found') {
    super(message, 404);
  }
}

export class LDAPConnectionError extends BaseError {
  constructor(message = 'LDAP connection failed') {
    super(message, 503);
  }
}

export class GraphAPIError extends BaseError {
  constructor(message = 'Graph API request failed') {
    super(message, 502);
  }
}

export class AuditExecutionError extends BaseError {
  constructor(message = 'Audit execution failed') {
    super(message, 500);
  }
}

export class TokenExpiredError extends BaseError {
  constructor(message = 'Token has expired') {
    super(message, 401);
  }
}

export class RateLimitError extends BaseError {
  constructor(message = 'Rate limit exceeded') {
    super(message, 429);
  }
}
