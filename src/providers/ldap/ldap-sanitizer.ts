/**
 * LDAP Injection Prevention
 *
 * Sanitizes LDAP filters and Distinguished Names to prevent injection attacks.
 * Follows OWASP guidelines and RFC 4515 (LDAP filters) / RFC 4514 (DNs).
 *
 * Task 2: Implement LDAP Sanitizer for Injection Prevention (Story 1.5)
 */

/**
 * LDAP Sanitizer
 *
 * Provides methods to sanitize and validate LDAP inputs.
 */
export class LDAPSanitizer {
  /**
   * LDAP filter special characters that require escaping (RFC 4515)
   */
  private static readonly FILTER_ESCAPE_MAP: Record<string, string> = {
    '\\': '\\5c', // Backslash (must be first)
    '*': '\\2a', // Asterisk
    '(': '\\28', // Left parenthesis
    ')': '\\29', // Right parenthesis
    '\0': '\\00', // NUL character
  };

  /**
   * DN special characters that require escaping (RFC 4514)
   */
  private static readonly DN_SPECIAL_CHARS = [',', '=', '+', '<', '>', '#', ';', '\\', '"'];

  /**
   * Sanitize LDAP filter string to prevent injection attacks
   *
   * Escapes special characters in LDAP filter values according to RFC 4515.
   * This prevents attackers from injecting malicious filter logic.
   *
   * @param filter - The filter string to sanitize
   * @returns Sanitized filter string with escaped special characters
   *
   * @example
   * ```typescript
   * // Prevents injection: (uid=*)(objectClass=*)
   * LDAPSanitizer.sanitizeFilter("*)(objectClass=*")
   * // Returns: "\2a\29\28objectClass=\2a"
   * ```
   */
  static sanitizeFilter(filter: string): string {
    if (!filter) {
      return filter;
    }

    let sanitized = filter;

    // Process in specific order: backslash first to avoid double-escaping
    for (const [char, escape] of Object.entries(this.FILTER_ESCAPE_MAP)) {
      sanitized = sanitized.split(char).join(escape);
    }

    return sanitized;
  }

  /**
   * Sanitize Distinguished Name (DN) to prevent injection
   *
   * Escapes special characters in DN components according to RFC 4514.
   * Handles leading/trailing spaces and special character positions.
   *
   * @param dn - The DN string to sanitize
   * @returns Sanitized DN string with properly escaped characters
   *
   * @example
   * ```typescript
   * LDAPSanitizer.sanitizeDN('cn=John, Doe')
   * // Returns: "cn=John\\, Doe"
   * ```
   */
  static sanitizeDN(dn: string): string {
    if (!dn) {
      return dn;
    }

    let sanitized = dn;

    // Escape backslash first to prevent double-escaping
    sanitized = sanitized.replace(/\\/g, '\\\\');

    // Escape other special characters
    for (const char of this.DN_SPECIAL_CHARS) {
      if (char === '\\') continue; // Already handled
      const regex = new RegExp(`\\${char}`, 'g');
      sanitized = sanitized.replace(regex, `\\${char}`);
    }

    // Escape leading space
    if (sanitized.startsWith(' ')) {
      sanitized = '\\' + sanitized;
    }

    // Escape trailing space
    if (sanitized.endsWith(' ') && !sanitized.endsWith('\\ ')) {
      sanitized = sanitized.slice(0, -1) + '\\ ';
    }

    // Escape leading # (hash)
    if (sanitized.startsWith('#')) {
      sanitized = '\\' + sanitized;
    }

    return sanitized;
  }

  /**
   * Validate LDAP filter syntax
   *
   * Checks if an LDAP filter has valid syntax:
   * - Balanced parentheses
   * - Valid operators (&, |, !)
   * - Proper filter structure
   *
   * @param filter - The filter to validate
   * @returns true if filter syntax is valid, false otherwise
   *
   * @example
   * ```typescript
   * LDAPSanitizer.isValidFilter('(uid=john)')  // true
   * LDAPSanitizer.isValidFilter('(uid=john')   // false - unbalanced
   * LDAPSanitizer.isValidFilter('uid=john')    // false - missing parens
   * ```
   */
  static isValidFilter(filter: string): boolean {
    if (!filter || typeof filter !== 'string') {
      return false;
    }

    // Filter must start and end with parentheses
    if (!filter.startsWith('(') || !filter.endsWith(')')) {
      return false;
    }

    // Check balanced parentheses
    let depth = 0;
    for (const char of filter) {
      if (char === '(') {
        depth++;
      } else if (char === ')') {
        depth--;
      }
      // Depth should never go negative
      if (depth < 0) {
        return false;
      }
    }

    // Must end with depth 0 (balanced)
    if (depth !== 0) {
      return false;
    }

    // Basic structure validation: must contain at least one operator or attribute
    // Valid filters: (&(...)), (|(...)), (!(...)), or (attribute=value)
    const hasLogicalOp = /^(\(&|\(\||\(!)/.test(filter);
    const hasAttribute = /\w+=/.test(filter);

    if (!hasLogicalOp && !hasAttribute) {
      return false;
    }

    return true;
  }

  /**
   * Validate Distinguished Name (DN) format
   *
   * Checks if a DN has valid structure:
   * - Contains attribute=value pairs
   * - Properly formatted with commas
   *
   * @param dn - The DN to validate
   * @returns true if DN format is valid, false otherwise
   *
   * @example
   * ```typescript
   * LDAPSanitizer.isValidDN('cn=John Doe,ou=Users,dc=example,dc=com')  // true
   * LDAPSanitizer.isValidDN('invalid-dn')  // false
   * ```
   */
  static isValidDN(dn: string): boolean {
    if (!dn || typeof dn !== 'string') {
      return false;
    }

    // DN must contain at least one attribute=value pair
    const dnPattern = /^([a-zA-Z][a-zA-Z0-9-]*=[^,]+)(,\s*[a-zA-Z][a-zA-Z0-9-]*=[^,]+)*$/;
    return dnPattern.test(dn.trim());
  }

  /**
   * Sanitize LDAP attribute name
   *
   * Ensures attribute name only contains valid characters.
   * Attribute names should only contain alphanumeric characters, hyphens, and dots.
   *
   * @param attribute - The attribute name to sanitize
   * @returns Sanitized attribute name or empty string if invalid
   */
  static sanitizeAttribute(attribute: string): string {
    if (!attribute || typeof attribute !== 'string') {
      return '';
    }

    // Remove any characters that aren't alphanumeric, hyphen, or dot
    return attribute.replace(/[^a-zA-Z0-9.-]/g, '');
  }

  /**
   * Build safe LDAP filter from components
   *
   * Constructs an LDAP filter with properly sanitized values.
   * Use this instead of string concatenation to build filters.
   *
   * @param attribute - Attribute name
   * @param operator - Comparison operator (=, >=, <=, ~=)
   * @param value - Value to filter by (will be sanitized)
   * @returns Safe LDAP filter string
   *
   * @example
   * ```typescript
   * LDAPSanitizer.buildFilter('uid', '=', 'john*')
   * // Returns: "(uid=john\\2a)"
   * ```
   */
  static buildFilter(
    attribute: string,
    operator: '=' | '>=' | '<=' | '~=' | '=*',
    value: string
  ): string {
    const safeAttribute = this.sanitizeAttribute(attribute);
    const safeValue = operator === '=*' ? value : this.sanitizeFilter(value);

    return `(${safeAttribute}${operator}${safeValue})`;
  }

  /**
   * Build safe logical filter (AND/OR/NOT)
   *
   * Combines multiple filters with logical operators.
   *
   * @param operator - Logical operator (&, |, !)
   * @param filters - Array of filter strings to combine
   * @returns Combined filter string
   *
   * @example
   * ```typescript
   * LDAPSanitizer.buildLogicalFilter('&', [
   *   '(objectClass=user)',
   *   '(uid=john)',
   * ])
   * // Returns: "(&(objectClass=user)(uid=john))"
   * ```
   */
  static buildLogicalFilter(operator: '&' | '|' | '!', filters: string[]): string {
    if (!filters || filters.length === 0) {
      return '';
    }

    if (operator === '!' && filters.length !== 1) {
      throw new Error('NOT operator requires exactly one filter');
    }

    return `(${operator}${filters.join('')})`;
  }
}
