/**
 * Unit Tests for Password Security Vulnerability Detector
 * Story 1.7: AD Vulnerability Detection Engine
 *
 * Tests all password-related vulnerability detectors:
 * - PASSWORD_NOT_REQUIRED
 * - REVERSIBLE_ENCRYPTION
 * - PASSWORD_NEVER_EXPIRES
 * - PASSWORD_VERY_OLD
 * - PASSWORD_IN_DESCRIPTION
 * - USER_CANNOT_CHANGE_PASSWORD
 * - UNIX_USER_PASSWORD
 */

import {
  detectPasswordNotRequired,
  detectReversibleEncryption,
  detectPasswordNeverExpires,
  detectPasswordVeryOld,
  detectPasswordInDescription,
  detectUserCannotChangePassword,
  detectUnixUserPassword,
} from '../../../../../../src/services/audit/detectors/ad/password.detector';
import { ADUser } from '../../../../../../src/types/ad.types';

describe('Password Security Detectors', () => {
  // Helper to create mock user
  const createUser = (overrides: Partial<ADUser> = {}): ADUser => ({
    dn: 'CN=TestUser,DC=example,DC=com',
    sAMAccountName: 'testuser',
    enabled: true,
    userAccountControl: 0,
    ...overrides,
  });

  describe('detectPasswordNotRequired', () => {
    it('should detect users with PASSWORD_NOT_REQUIRED flag (0x20)', () => {
      const users: ADUser[] = [
        createUser({ sAMAccountName: 'user1', userAccountControl: 0x20 }), // Has flag
        createUser({ sAMAccountName: 'user2', userAccountControl: 0x00 }), // Normal
        createUser({ sAMAccountName: 'user3', userAccountControl: 0x220 }), // Has flag + others
      ];

      const result = detectPasswordNotRequired(users, false);

      expect(result.type).toBe('PASSWORD_NOT_REQUIRED');
      expect(result.severity).toBe('critical');
      expect(result.category).toBe('passwords');
      expect(result.count).toBe(2); // user1 and user3
      expect(result.affectedEntities).toBeUndefined(); // includeDetails=false
    });

    it('should return details when includeDetails=true', () => {
      const users: ADUser[] = [
        createUser({ sAMAccountName: 'user1', userAccountControl: 0x20 }),
      ];

      const result = detectPasswordNotRequired(users, true);

      expect(result.affectedEntities).toBeDefined();
      expect(result.affectedEntities).toHaveLength(1);
      expect(result.affectedEntities?.[0]).toContain('CN=TestUser');
    });

    it('should return 0 when no users have the flag', () => {
      const users: ADUser[] = [
        createUser({ userAccountControl: 0x00 }),
        createUser({ userAccountControl: 0x200 }),
      ];

      const result = detectPasswordNotRequired(users, false);

      expect(result.count).toBe(0);
    });

    it('should handle empty user list', () => {
      const result = detectPasswordNotRequired([], false);
      expect(result.count).toBe(0);
    });

    it('should handle users without userAccountControl', () => {
      const users: ADUser[] = [
        createUser({ userAccountControl: undefined }),
      ];

      const result = detectPasswordNotRequired(users, false);
      expect(result.count).toBe(0);
    });
  });

  describe('detectReversibleEncryption', () => {
    it('should detect users with REVERSIBLE_ENCRYPTION flag (0x80)', () => {
      const users: ADUser[] = [
        createUser({ sAMAccountName: 'user1', userAccountControl: 0x80 }),
        createUser({ sAMAccountName: 'user2', userAccountControl: 0x00 }),
        createUser({ sAMAccountName: 'user3', userAccountControl: 0x280 }),
      ];

      const result = detectReversibleEncryption(users, false);

      expect(result.type).toBe('REVERSIBLE_ENCRYPTION');
      expect(result.severity).toBe('critical');
      expect(result.count).toBe(2);
    });
  });

  describe('detectPasswordNeverExpires', () => {
    it('should detect users with PASSWORD_NEVER_EXPIRES flag (0x10000)', () => {
      const users: ADUser[] = [
        createUser({ sAMAccountName: 'user1', userAccountControl: 0x10000 }),
        createUser({ sAMAccountName: 'user2', userAccountControl: 0x00 }),
      ];

      const result = detectPasswordNeverExpires(users, false);

      expect(result.type).toBe('PASSWORD_NEVER_EXPIRES');
      expect(result.severity).toBe('critical');
      expect(result.count).toBe(1);
    });
  });

  describe('detectPasswordVeryOld', () => {
    it('should detect passwords older than 365 days', () => {
      const now = new Date();
      const old = new Date(now.getTime() - 366 * 24 * 60 * 60 * 1000); // 366 days ago
      const recent = new Date(now.getTime() - 100 * 24 * 60 * 60 * 1000); // 100 days ago

      const users: ADUser[] = [
        createUser({ sAMAccountName: 'user1', passwordLastSet: old }),
        createUser({ sAMAccountName: 'user2', passwordLastSet: recent }),
        createUser({ sAMAccountName: 'user3', passwordLastSet: undefined }),
      ];

      const result = detectPasswordVeryOld(users, false);

      expect(result.type).toBe('PASSWORD_VERY_OLD');
      expect(result.severity).toBe('medium');
      expect(result.count).toBe(1);
    });
  });

  describe('detectPasswordInDescription', () => {
    it('should detect passwords in description field', () => {
      const users: ADUser[] = [
        createUser({
          sAMAccountName: 'user1',
          description: 'Password: MySecret123'
        } as any),
        createUser({
          sAMAccountName: 'user2',
          description: 'pwd=P@ssw0rd'
        } as any),
        createUser({
          sAMAccountName: 'user3',
          description: 'Normal description'
        } as any),
      ];

      const result = detectPasswordInDescription(users, false);

      expect(result.type).toBe('PASSWORD_IN_DESCRIPTION');
      expect(result.severity).toBe('high');
      expect(result.count).toBe(2);
    });

    it('should detect case-insensitive password mentions', () => {
      const users: ADUser[] = [
        createUser({ description: 'PASSWORD: secret' } as any),
        createUser({ description: 'Motdepasse: test123' } as any),
      ];

      const result = detectPasswordInDescription(users, false);
      expect(result.count).toBe(2);
    });
  });

  describe('detectUserCannotChangePassword', () => {
    it('should detect users who cannot change their password', () => {
      const users: ADUser[] = [
        createUser({ sAMAccountName: 'user1', userAccountControl: 0x40 }),
        createUser({ sAMAccountName: 'user2', userAccountControl: 0x00 }),
      ];

      const result = detectUserCannotChangePassword(users, false);

      expect(result.type).toBe('USER_CANNOT_CHANGE_PASSWORD');
      expect(result.severity).toBe('medium');
      expect(result.count).toBe(1);
    });
  });

  describe('detectUnixUserPassword', () => {
    it('should detect users with unixUserPassword attribute', () => {
      const users: ADUser[] = [
        createUser({ sAMAccountName: 'user1', unixUserPassword: 'plaintext' } as any),
        createUser({ sAMAccountName: 'user2' }),
      ];

      const result = detectUnixUserPassword(users, false);

      expect(result.type).toBe('UNIX_USER_PASSWORD');
      expect(result.severity).toBe('critical');
      expect(result.count).toBe(1);
    });
  });

  describe('Integration Tests', () => {
    it('should handle multiple vulnerabilities on same user', () => {
      const users: ADUser[] = [
        createUser({
          sAMAccountName: 'baduser',
          userAccountControl: 0x100A0, // Multiple flags
          description: 'Password: test123',
        } as any),
      ];

      const notRequired = detectPasswordNotRequired(users, false);
      const reversible = detectReversibleEncryption(users, false);
      const neverExpires = detectPasswordNeverExpires(users, false);
      const inDescription = detectPasswordInDescription(users, false);

      // This user should trigger multiple detections
      expect(notRequired.count + reversible.count + neverExpires.count + inDescription.count).toBeGreaterThan(0);
    });
  });
});
