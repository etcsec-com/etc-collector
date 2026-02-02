/**
 * Unit Tests for Accounts Security Vulnerability Detector
 * Story 1.7: AD Vulnerability Detection Engine
 *
 * Tests all account-related vulnerability detectors:
 * - SENSITIVE_DELEGATION
 * - DISABLED_ACCOUNT_IN_ADMIN_GROUP
 * - EXPIRED_ACCOUNT_IN_ADMIN_GROUP
 * - SID_HISTORY
 * - NOT_IN_PROTECTED_USERS
 * - DOMAIN_ADMIN_IN_DESCRIPTION
 * - BACKUP_OPERATORS_MEMBER
 * - ACCOUNT_OPERATORS_MEMBER
 * - SERVER_OPERATORS_MEMBER
 * - PRINT_OPERATORS_MEMBER
 * - INACTIVE_365_DAYS
 * - TEST_ACCOUNT
 * - SHARED_ACCOUNT
 * - SMARTCARD_NOT_REQUIRED
 * - PRIMARYGROUPID_SPOOFING
 */

import {
  detectSensitiveDelegation,
  detectDisabledAccountInAdminGroup,
  detectExpiredAccountInAdminGroup,
  detectSidHistory,
  detectNotInProtectedUsers,
  detectDomainAdminInDescription,
  detectBackupOperatorsMember,
  detectAccountOperatorsMember,
  detectServerOperatorsMember,
  detectPrintOperatorsMember,
  detectInactive365Days,
  detectTestAccount,
  detectSharedAccount,
  detectSmartcardNotRequired,
  detectPrimaryGroupIdSpoofing,
} from '../../../../../../src/services/audit/detectors/ad/accounts.detector';
import { ADUser } from '../../../../../../src/types/ad.types';

describe('Accounts Security Detectors', () => {
  const createUser = (overrides: Partial<ADUser> = {}): ADUser => ({
    dn: 'CN=TestUser,DC=example,DC=com',
    sAMAccountName: 'testuser',
    enabled: true,
    userAccountControl: 0,
    ...overrides,
  });

  describe('detectSensitiveDelegation', () => {
    it('should detect privileged accounts with unconstrained delegation', () => {
      const users: ADUser[] = [
        createUser({
          sAMAccountName: 'admin1',
          userAccountControl: 0x80000, // Unconstrained delegation
          memberOf: ['CN=Domain Admins,DC=example,DC=com'],
        }),
        createUser({
          sAMAccountName: 'normaluser',
          userAccountControl: 0x80000,
          memberOf: ['CN=Users,DC=example,DC=com'],
        }),
        createUser({
          sAMAccountName: 'admin2',
          userAccountControl: 0x00,
          memberOf: ['CN=Domain Admins,DC=example,DC=com'],
        }),
      ];

      const result = detectSensitiveDelegation(users, false);

      expect(result.type).toBe('SENSITIVE_DELEGATION');
      expect(result.severity).toBe('critical');
      expect(result.category).toBe('accounts');
      expect(result.count).toBe(1); // Only admin1
    });
  });

  describe('detectDisabledAccountInAdminGroup', () => {
    it('should detect disabled accounts in admin groups', () => {
      const users: ADUser[] = [
        createUser({
          sAMAccountName: 'oldadmin',
          userAccountControl: 0x2, // ACCOUNTDISABLE
          memberOf: ['CN=Domain Admins,DC=example,DC=com'],
        }),
        createUser({
          sAMAccountName: 'enabledadmin',
          userAccountControl: 0x0,
          memberOf: ['CN=Domain Admins,DC=example,DC=com'],
        }),
      ];

      const result = detectDisabledAccountInAdminGroup(users, false);

      expect(result.type).toBe('DISABLED_ACCOUNT_IN_ADMIN_GROUP');
      expect(result.severity).toBe('high');
      expect(result.count).toBe(1);
    });
  });

  describe('detectExpiredAccountInAdminGroup', () => {
    it('should detect expired accounts in admin groups', () => {
      const now = new Date();
      const past = new Date(now.getTime() - 100 * 24 * 60 * 60 * 1000); // 100 days ago
      const future = new Date(now.getTime() + 100 * 24 * 60 * 60 * 1000); // 100 days future

      const users: ADUser[] = [
        createUser({
          sAMAccountName: 'expiredadmin',
          accountExpires: past,
          memberOf: ['CN=Domain Admins,DC=example,DC=com'],
        } as any),
        createUser({
          sAMAccountName: 'validadmin',
          accountExpires: future,
          memberOf: ['CN=Domain Admins,DC=example,DC=com'],
        } as any),
      ];

      const result = detectExpiredAccountInAdminGroup(users, false);

      expect(result.type).toBe('EXPIRED_ACCOUNT_IN_ADMIN_GROUP');
      expect(result.severity).toBe('high');
      expect(result.count).toBe(1);
    });
  });

  describe('detectSidHistory', () => {
    it('should detect users with SID history', () => {
      const users: ADUser[] = [
        createUser({
          sAMAccountName: 'migrateduser',
          sIDHistory: ['S-1-5-21-1234567890-1234567890-1234567890-500'],
        } as any),
        createUser({ sAMAccountName: 'normaluser' }),
      ];

      const result = detectSidHistory(users, false);

      expect(result.type).toBe('SID_HISTORY');
      expect(result.severity).toBe('high');
      expect(result.count).toBe(1);
    });
  });

  describe('detectNotInProtectedUsers', () => {
    it('should detect privileged users not in Protected Users', () => {
      const users: ADUser[] = [
        createUser({
          sAMAccountName: 'admin1',
          memberOf: [
            'CN=Domain Admins,DC=example,DC=com',
            'CN=Protected Users,DC=example,DC=com',
          ],
        }),
        createUser({
          sAMAccountName: 'admin2',
          memberOf: ['CN=Domain Admins,DC=example,DC=com'],
        }),
        createUser({
          sAMAccountName: 'normaluser',
          memberOf: ['CN=Users,DC=example,DC=com'],
        }),
      ];

      const result = detectNotInProtectedUsers(users, false);

      expect(result.type).toBe('NOT_IN_PROTECTED_USERS');
      expect(result.severity).toBe('high');
      expect(result.count).toBe(1); // Only admin2
    });
  });

  describe('detectDomainAdminInDescription', () => {
    it('should detect sensitive keywords in description', () => {
      const users: ADUser[] = [
        createUser({ description: 'Domain Admin account for IT' } as any),
        createUser({ description: 'Enterprise Admin user' } as any),
        createUser({ description: 'Regular user account' } as any),
        createUser({ description: 'Privileged access required' } as any),
      ];

      const result = detectDomainAdminInDescription(users, false);

      expect(result.type).toBe('DOMAIN_ADMIN_IN_DESCRIPTION');
      expect(result.severity).toBe('high');
      expect(result.count).toBe(3);
    });
  });

  describe('detectBackupOperatorsMember', () => {
    it('should detect Backup Operators membership', () => {
      const users: ADUser[] = [
        createUser({
          sAMAccountName: 'backupuser',
          memberOf: ['CN=Backup Operators,DC=example,DC=com'],
        }),
        createUser({ sAMAccountName: 'normaluser', memberOf: ['CN=Users,DC=example,DC=com'] }),
      ];

      const result = detectBackupOperatorsMember(users, false);

      expect(result.type).toBe('BACKUP_OPERATORS_MEMBER');
      expect(result.severity).toBe('high');
      expect(result.count).toBe(1);
    });
  });

  describe('detectAccountOperatorsMember', () => {
    it('should detect Account Operators membership', () => {
      const users: ADUser[] = [
        createUser({
          sAMAccountName: 'accountop',
          memberOf: ['CN=Account Operators,DC=example,DC=com'],
        }),
        createUser({ sAMAccountName: 'normaluser', memberOf: [] }),
      ];

      const result = detectAccountOperatorsMember(users, false);

      expect(result.type).toBe('ACCOUNT_OPERATORS_MEMBER');
      expect(result.severity).toBe('high');
      expect(result.count).toBe(1);
    });
  });

  describe('detectServerOperatorsMember', () => {
    it('should detect Server Operators membership', () => {
      const users: ADUser[] = [
        createUser({
          sAMAccountName: 'serverop',
          memberOf: ['CN=Server Operators,DC=example,DC=com'],
        }),
        createUser({ sAMAccountName: 'normaluser' }),
      ];

      const result = detectServerOperatorsMember(users, false);

      expect(result.type).toBe('SERVER_OPERATORS_MEMBER');
      expect(result.severity).toBe('high');
      expect(result.count).toBe(1);
    });
  });

  describe('detectPrintOperatorsMember', () => {
    it('should detect Print Operators membership', () => {
      const users: ADUser[] = [
        createUser({
          sAMAccountName: 'printop',
          memberOf: ['CN=Print Operators,DC=example,DC=com'],
        }),
        createUser({ sAMAccountName: 'normaluser' }),
      ];

      const result = detectPrintOperatorsMember(users, false);

      expect(result.type).toBe('PRINT_OPERATORS_MEMBER');
      expect(result.severity).toBe('high');
      expect(result.count).toBe(1);
    });
  });

  describe('detectInactive365Days', () => {
    it('should detect accounts inactive for 365+ days', () => {
      const now = new Date();
      const old = new Date(now.getTime() - 400 * 24 * 60 * 60 * 1000); // 400 days ago
      const recent = new Date(now.getTime() - 100 * 24 * 60 * 60 * 1000); // 100 days ago

      const users: ADUser[] = [
        createUser({ sAMAccountName: 'staleuser', lastLogon: old }),
        createUser({ sAMAccountName: 'activeuser', lastLogon: recent }),
        createUser({ sAMAccountName: 'nologon' }),
      ];

      const result = detectInactive365Days(users, false);

      expect(result.type).toBe('INACTIVE_365_DAYS');
      expect(result.severity).toBe('medium');
      expect(result.count).toBe(1);
    });
  });

  describe('detectTestAccount', () => {
    it('should detect test/demo/temp accounts', () => {
      const users: ADUser[] = [
        createUser({ sAMAccountName: 'testuser1' }),
        createUser({ sAMAccountName: 'user_test' }),
        createUser({ sAMAccountName: 'demo123' }),
        createUser({ sAMAccountName: 'tempaccount' }),
        createUser({ sAMAccountName: 'normaluser' }),
      ];

      const result = detectTestAccount(users, false);

      expect(result.type).toBe('TEST_ACCOUNT');
      expect(result.severity).toBe('medium');
      expect(result.count).toBe(4);
    });
  });

  describe('detectSharedAccount', () => {
    it('should detect shared/generic/service accounts', () => {
      const users: ADUser[] = [
        createUser({ sAMAccountName: 'sharedadmin' }),
        createUser({ sAMAccountName: 'commonaccount' }),
        createUser({ sAMAccountName: 'genericuser' }),
        createUser({ sAMAccountName: 'serviceacct' }),
        createUser({ sAMAccountName: 'svc_backup' }),
        createUser({ sAMAccountName: 'john.doe' }),
      ];

      const result = detectSharedAccount(users, false);

      expect(result.type).toBe('SHARED_ACCOUNT');
      expect(result.severity).toBe('medium');
      expect(result.count).toBe(5);
    });
  });

  describe('detectSmartcardNotRequired', () => {
    it('should detect smartcard not required flag (0x40000)', () => {
      const users: ADUser[] = [
        createUser({ sAMAccountName: 'user1', userAccountControl: 0x40000 }),
        createUser({ sAMAccountName: 'user2', userAccountControl: 0x00 }),
        createUser({ sAMAccountName: 'user3', userAccountControl: 0x40200 }),
      ];

      const result = detectSmartcardNotRequired(users, false);

      expect(result.type).toBe('SMARTCARD_NOT_REQUIRED');
      expect(result.severity).toBe('medium');
      expect(result.count).toBe(2);
    });
  });

  describe('detectPrimaryGroupIdSpoofing', () => {
    it('should detect non-standard primaryGroupID', () => {
      const users: ADUser[] = [
        createUser({ sAMAccountName: 'user1', primaryGroupID: 513 } as any), // Normal Domain Users
        createUser({ sAMAccountName: 'user2', primaryGroupID: 512 } as any), // Domain Admins
        createUser({ sAMAccountName: 'user3', primaryGroupID: 515 } as any), // Domain Computers
        createUser({ sAMAccountName: 'user4' }), // No primaryGroupID
      ];

      const result = detectPrimaryGroupIdSpoofing(users, false);

      expect(result.type).toBe('PRIMARYGROUPID_SPOOFING');
      expect(result.severity).toBe('medium');
      expect(result.count).toBe(2); // user2 and user3
    });
  });

  describe('Integration Tests', () => {
    it('should handle user with multiple account vulnerabilities', () => {
      const users: ADUser[] = [
        createUser({
          sAMAccountName: 'testadmin',
          userAccountControl: 0x80002, // Disabled + unconstrained delegation
          memberOf: ['CN=Domain Admins,DC=example,DC=com'],
          description: 'Domain Admin test account',
        } as any),
      ];

      const sensitive = detectSensitiveDelegation(users, false);
      const disabled = detectDisabledAccountInAdminGroup(users, false);
      const description = detectDomainAdminInDescription(users, false);
      const test = detectTestAccount(users, false);

      const totalVulns = sensitive.count + disabled.count + description.count + test.count;
      expect(totalVulns).toBeGreaterThan(0);
    });

    it('should return 0 for users with no vulnerabilities', () => {
      const users: ADUser[] = [
        createUser({
          sAMAccountName: 'john.doe',
          userAccountControl: 0x200, // Normal enabled account
          memberOf: ['CN=Users,DC=example,DC=com'],
        }),
      ];

      const sensitive = detectSensitiveDelegation(users, false);
      const disabled = detectDisabledAccountInAdminGroup(users, false);
      const test = detectTestAccount(users, false);

      expect(sensitive.count).toBe(0);
      expect(disabled.count).toBe(0);
      expect(test.count).toBe(0);
    });
  });
});
