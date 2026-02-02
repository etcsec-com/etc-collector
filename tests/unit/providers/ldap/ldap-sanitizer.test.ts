import { LDAPSanitizer } from '../../../../src/providers/ldap/ldap-sanitizer';

/**
 * Unit Tests for LDAP Sanitizer
 * Task 8: Write Unit Tests for LDAP Provider (Story 1.5)
 */

describe('LDAPSanitizer', () => {
  describe('sanitizeFilter', () => {
    it('should escape backslash characters', () => {
      const input = 'user\\name';
      const result = LDAPSanitizer.sanitizeFilter(input);
      expect(result).toBe('user\\5cname');
    });

    it('should escape asterisk characters', () => {
      const input = 'user*';
      const result = LDAPSanitizer.sanitizeFilter(input);
      expect(result).toBe('user\\2a');
    });

    it('should escape parentheses', () => {
      const input = 'user(name)';
      const result = LDAPSanitizer.sanitizeFilter(input);
      expect(result).toBe('user\\28name\\29');
    });

    it('should escape NUL character', () => {
      const input = 'user\0name';
      const result = LDAPSanitizer.sanitizeFilter(input);
      expect(result).toBe('user\\00name');
    });

    it('should prevent LDAP injection with multiple special chars', () => {
      const maliciousInput = '*)(objectClass=*)';
      const result = LDAPSanitizer.sanitizeFilter(maliciousInput);
      expect(result).toBe('\\2a\\29\\28objectClass=\\2a\\29');
    });

    it('should handle empty string', () => {
      const result = LDAPSanitizer.sanitizeFilter('');
      expect(result).toBe('');
    });

    it('should handle string with no special characters', () => {
      const input = 'john.doe';
      const result = LDAPSanitizer.sanitizeFilter(input);
      expect(result).toBe('john.doe');
    });

    it('should escape backslash before other special chars to prevent double-escaping', () => {
      const input = '\\*';
      const result = LDAPSanitizer.sanitizeFilter(input);
      expect(result).toBe('\\5c\\2a');
    });
  });

  describe('sanitizeDN', () => {
    it('should escape comma in DN value', () => {
      const input = 'John, Doe';
      const result = LDAPSanitizer.sanitizeDN(input);
      expect(result).toBe('John\\, Doe');
    });

    it('should escape equals sign in value', () => {
      const input = 'user=name';
      const result = LDAPSanitizer.sanitizeDN(input);
      expect(result).toBe('user\\=name');
    });

    it('should escape plus sign in value', () => {
      const input = 'test+value';
      const result = LDAPSanitizer.sanitizeDN(input);
      expect(result).toBe('test\\+value');
    });

    it('should escape leading space', () => {
      const input = ' leading';
      const result = LDAPSanitizer.sanitizeDN(input);
      expect(result).toBe('\\ leading');
    });

    it('should escape trailing space', () => {
      const input = 'trailing ';
      const result = LDAPSanitizer.sanitizeDN(input);
      expect(result).toBe('trailing\\ ');
    });

    it('should escape leading hash', () => {
      const input = '#hash';
      const result = LDAPSanitizer.sanitizeDN(input);
      expect(result).toBe('\\#hash');
    });

    it('should escape backslash in value', () => {
      const input = 'test\\value';
      const result = LDAPSanitizer.sanitizeDN(input);
      expect(result).toBe('test\\\\value');
    });

    it('should handle empty string', () => {
      const result = LDAPSanitizer.sanitizeDN('');
      expect(result).toBe('');
    });

    it('should handle simple value with no special characters', () => {
      const input = 'JohnDoe';
      const result = LDAPSanitizer.sanitizeDN(input);
      expect(result).toBe('JohnDoe');
    });
  });

  describe('isValidFilter', () => {
    it('should validate simple filter', () => {
      const result = LDAPSanitizer.isValidFilter('(uid=john)');
      expect(result).toBe(true);
    });

    it('should validate AND filter', () => {
      const result = LDAPSanitizer.isValidFilter('(&(uid=john)(objectClass=person))');
      expect(result).toBe(true);
    });

    it('should validate OR filter', () => {
      const result = LDAPSanitizer.isValidFilter('(|(uid=john)(uid=jane))');
      expect(result).toBe(true);
    });

    it('should validate NOT filter', () => {
      const result = LDAPSanitizer.isValidFilter('(!(uid=admin))');
      expect(result).toBe(true);
    });

    it('should reject filter without parentheses', () => {
      const result = LDAPSanitizer.isValidFilter('uid=john');
      expect(result).toBe(false);
    });

    it('should reject filter with unbalanced parentheses', () => {
      const result = LDAPSanitizer.isValidFilter('(uid=john');
      expect(result).toBe(false);
    });

    it('should reject filter with extra closing parenthesis', () => {
      const result = LDAPSanitizer.isValidFilter('(uid=john))');
      expect(result).toBe(false);
    });

    it('should reject empty string', () => {
      const result = LDAPSanitizer.isValidFilter('');
      expect(result).toBe(false);
    });

    it('should reject empty parentheses', () => {
      const result = LDAPSanitizer.isValidFilter('()');
      expect(result).toBe(false);
    });

    it('should validate complex nested filter', () => {
      const result = LDAPSanitizer.isValidFilter(
        '(&(objectClass=user)(|(uid=john)(mail=john@example.com)))'
      );
      expect(result).toBe(true);
    });
  });

  describe('isValidDN', () => {
    it('should validate simple DN', () => {
      const result = LDAPSanitizer.isValidDN('cn=John Doe');
      expect(result).toBe(true);
    });

    it('should validate full DN', () => {
      const result = LDAPSanitizer.isValidDN('cn=John Doe,ou=Users,dc=example,dc=com');
      expect(result).toBe(true);
    });

    it('should validate DN with spaces', () => {
      const result = LDAPSanitizer.isValidDN('cn=John Doe, ou=Users, dc=example, dc=com');
      expect(result).toBe(true);
    });

    it('should reject invalid DN format', () => {
      const result = LDAPSanitizer.isValidDN('invalid-dn');
      expect(result).toBe(false);
    });

    it('should reject empty string', () => {
      const result = LDAPSanitizer.isValidDN('');
      expect(result).toBe(false);
    });

    it('should reject DN with invalid attribute name', () => {
      const result = LDAPSanitizer.isValidDN('123invalid=value');
      expect(result).toBe(false);
    });
  });

  describe('sanitizeAttribute', () => {
    it('should allow valid attribute names', () => {
      const result = LDAPSanitizer.sanitizeAttribute('sAMAccountName');
      expect(result).toBe('sAMAccountName');
    });

    it('should allow attributes with hyphens', () => {
      const result = LDAPSanitizer.sanitizeAttribute('user-name');
      expect(result).toBe('user-name');
    });

    it('should allow attributes with dots', () => {
      const result = LDAPSanitizer.sanitizeAttribute('user.name');
      expect(result).toBe('user.name');
    });

    it('should remove special characters', () => {
      const result = LDAPSanitizer.sanitizeAttribute('user@name!');
      expect(result).toBe('username');
    });

    it('should handle empty string', () => {
      const result = LDAPSanitizer.sanitizeAttribute('');
      expect(result).toBe('');
    });
  });

  describe('buildFilter', () => {
    it('should build simple equality filter', () => {
      const result = LDAPSanitizer.buildFilter('uid', '=', 'john');
      expect(result).toBe('(uid=john)');
    });

    it('should sanitize filter value', () => {
      const result = LDAPSanitizer.buildFilter('uid', '=', 'john*');
      expect(result).toBe('(uid=john\\2a)');
    });

    it('should build greater-than filter', () => {
      const result = LDAPSanitizer.buildFilter('age', '>=', '18');
      expect(result).toBe('(age>=18)');
    });

    it('should build less-than filter', () => {
      const result = LDAPSanitizer.buildFilter('age', '<=', '65');
      expect(result).toBe('(age<=65)');
    });

    it('should build approximate filter', () => {
      const result = LDAPSanitizer.buildFilter('name', '~=', 'john');
      expect(result).toBe('(name~=john)');
    });

    it('should allow wildcards with =* operator', () => {
      const result = LDAPSanitizer.buildFilter('uid', '=*', '*john*');
      expect(result).toBe('(uid=**john*)');
    });

    it('should sanitize attribute name', () => {
      const result = LDAPSanitizer.buildFilter('user@name', '=', 'john');
      expect(result).toBe('(username=john)');
    });
  });

  describe('buildLogicalFilter', () => {
    it('should build AND filter', () => {
      const result = LDAPSanitizer.buildLogicalFilter('&', [
        '(uid=john)',
        '(objectClass=person)',
      ]);
      expect(result).toBe('(&(uid=john)(objectClass=person))');
    });

    it('should build OR filter', () => {
      const result = LDAPSanitizer.buildLogicalFilter('|', ['(uid=john)', '(uid=jane)']);
      expect(result).toBe('(|(uid=john)(uid=jane))');
    });

    it('should build NOT filter', () => {
      const result = LDAPSanitizer.buildLogicalFilter('!', ['(uid=admin)']);
      expect(result).toBe('(!(uid=admin))');
    });

    it('should handle empty array', () => {
      const result = LDAPSanitizer.buildLogicalFilter('&', []);
      expect(result).toBe('');
    });

    it('should throw error for NOT with multiple filters', () => {
      expect(() => {
        LDAPSanitizer.buildLogicalFilter('!', ['(uid=john)', '(uid=jane)']);
      }).toThrow('NOT operator requires exactly one filter');
    });

    it('should handle nested filters', () => {
      const result = LDAPSanitizer.buildLogicalFilter('&', [
        '(objectClass=user)',
        '(|(uid=john)(mail=john@example.com))',
      ]);
      expect(result).toBe('(&(objectClass=user)(|(uid=john)(mail=john@example.com)))');
    });
  });
});
