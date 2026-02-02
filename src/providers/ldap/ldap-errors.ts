/**
 * LDAP Error Types
 *
 * Custom error classes for LDAP operations.
 * Provides specific error types for different failure scenarios.
 *
 * Task 7: Create Error Types for LDAP Operations (Story 1.5)
 */

/**
 * Base LDAP Error
 *
 * Base class for all LDAP-related errors.
 */
export class LDAPError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'LDAPError';
    Object.setPrototypeOf(this, LDAPError.prototype);
  }
}

/**
 * LDAP Connection Error
 *
 * Thrown when connection to LDAP server fails.
 */
export class LDAPConnectionError extends LDAPError {
  public readonly url: string;
  public override readonly cause?: Error;

  constructor(message: string, url: string, cause?: Error) {
    super(message);
    this.name = 'LDAPConnectionError';
    this.url = url;
    this.cause = cause;
    Object.setPrototypeOf(this, LDAPConnectionError.prototype);
  }
}

/**
 * LDAP Authentication Error
 *
 * Thrown when LDAP bind/authentication fails.
 */
export class LDAPAuthenticationError extends LDAPError {
  public readonly bindDN: string;

  constructor(message: string, bindDN: string) {
    super(message);
    this.name = 'LDAPAuthenticationError';
    this.bindDN = bindDN;
    Object.setPrototypeOf(this, LDAPAuthenticationError.prototype);
  }
}

/**
 * LDAP Search Error
 *
 * Thrown when LDAP search operation fails.
 */
export class LDAPSearchError extends LDAPError {
  public readonly baseDN: string;
  public readonly filter: string;
  public override readonly cause?: Error;

  constructor(message: string, baseDN: string, filter: string, cause?: Error) {
    super(message);
    this.name = 'LDAPSearchError';
    this.baseDN = baseDN;
    this.filter = filter;
    this.cause = cause;
    Object.setPrototypeOf(this, LDAPSearchError.prototype);
  }
}

/**
 * LDAP Timeout Error
 *
 * Thrown when LDAP operation times out.
 */
export class LDAPTimeoutError extends LDAPError {
  public readonly operation: string;
  public readonly timeoutMs: number;

  constructor(message: string, operation: string, timeoutMs: number) {
    super(message);
    this.name = 'LDAPTimeoutError';
    this.operation = operation;
    this.timeoutMs = timeoutMs;
    Object.setPrototypeOf(this, LDAPTimeoutError.prototype);
  }
}

/**
 * LDAP Invalid Filter Error
 *
 * Thrown when LDAP filter syntax is invalid.
 */
export class LDAPInvalidFilterError extends LDAPError {
  public readonly filter: string;

  constructor(message: string, filter: string) {
    super(message);
    this.name = 'LDAPInvalidFilterError';
    this.filter = filter;
    Object.setPrototypeOf(this, LDAPInvalidFilterError.prototype);
  }
}

/**
 * LDAP Invalid DN Error
 *
 * Thrown when Distinguished Name is invalid.
 */
export class LDAPInvalidDNError extends LDAPError {
  public readonly dn: string;

  constructor(message: string, dn: string) {
    super(message);
    this.name = 'LDAPInvalidDNError';
    this.dn = dn;
    Object.setPrototypeOf(this, LDAPInvalidDNError.prototype);
  }
}

/**
 * LDAP Injection Attempt Error
 *
 * Thrown when LDAP injection is detected.
 */
export class LDAPInjectionAttemptError extends LDAPError {
  public readonly input: string;

  constructor(message: string, input: string) {
    super(message);
    this.name = 'LDAPInjectionAttemptError';
    this.input = input;
    Object.setPrototypeOf(this, LDAPInjectionAttemptError.prototype);
  }
}

/**
 * LDAP Not Connected Error
 *
 * Thrown when operation attempted without connection.
 */
export class LDAPNotConnectedError extends LDAPError {
  constructor(message: string = 'LDAP client not connected') {
    super(message);
    this.name = 'LDAPNotConnectedError';
    Object.setPrototypeOf(this, LDAPNotConnectedError.prototype);
  }
}

/**
 * LDAP Configuration Error
 *
 * Thrown when LDAP configuration is invalid.
 */
export class LDAPConfigurationError extends LDAPError {
  public readonly configKey: string;

  constructor(message: string, configKey: string) {
    super(message);
    this.name = 'LDAPConfigurationError';
    this.configKey = configKey;
    Object.setPrototypeOf(this, LDAPConfigurationError.prototype);
  }
}

/**
 * LDAP Size Limit Exceeded Error
 *
 * Thrown when search result exceeds size limit.
 */
export class LDAPSizeLimitExceededError extends LDAPError {
  public readonly limit: number;
  public readonly returned: number;

  constructor(message: string, limit: number, returned: number) {
    super(message);
    this.name = 'LDAPSizeLimitExceededError';
    this.limit = limit;
    this.returned = returned;
    Object.setPrototypeOf(this, LDAPSizeLimitExceededError.prototype);
  }
}
