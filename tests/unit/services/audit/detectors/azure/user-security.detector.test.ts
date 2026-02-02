/**
 * Unit Tests for User Security Vulnerability Detector
 * Story 1.8: Azure Vulnerability Detection Engine
 *
 * Tests all user-related vulnerability detectors (10 types):
 * - AZURE_GLOBAL_ADMIN_NO_MFA
 * - AZURE_PRIVILEGED_USER_NO_MFA
 * - AZURE_RISKY_USER_HIGH
 * - AZURE_USER_INACTIVE
 * - AZURE_USER_PASSWORD_NEVER_EXPIRES
 * - AZURE_RISKY_USER_MEDIUM
 * - AZURE_PASSWORD_OLD
 * - AZURE_USER_NEVER_SIGNED_IN
 * - AZURE_USER_UNLICENSED
 * - AZURE_USER_EXTERNAL_MEMBER
 */

import {
  detectGlobalAdminNoMfa,
  detectPrivilegedUserNoMfa,
  detectRiskyUserHigh,
  detectUserInactive,
  detectPasswordNeverExpires,
  detectRiskyUserMedium,
  detectPasswordOld,
  detectUserNeverSignedIn,
  detectUserUnlicensed,
  detectUserExternalMember,
  detectUserSecurityVulnerabilities,
} from '../../../../../../src/services/audit/detectors/azure/user-security.detector';
import { AzureUser } from '../../../../../../src/types/azure.types';

describe('User Security Detectors', () => {
  const createUser = (overrides: Partial<AzureUser> = {}): AzureUser => ({
    id: 'user-123',
    userPrincipalName: 'test@example.com',
    displayName: 'Test User',
    mail: 'test@example.com',
    accountEnabled: true,
    ...overrides,
  });

  const globalAdminRoleId = '62e90394-69f5-4237-9190-012177145e10';

  describe('detectGlobalAdminNoMfa', () => {
    it('should detect Global Admin without MFA', () => {
      const users: AzureUser[] = [
        createUser({ id: 'admin-1' }),
        createUser({ id: 'user-1' }),
      ];

      const roles = new Map<string, string[]>([['admin-1', [globalAdminRoleId]]]);

      const result = detectGlobalAdminNoMfa(users, roles, false);

      expect(result.type).toBe('AZURE_GLOBAL_ADMIN_NO_MFA');
      expect(result.severity).toBe('critical');
      expect(result.category).toBe('identity');
      expect(result.count).toBe(1);
    });

    it('should not detect Global Admin with MFA', () => {
      const users: AzureUser[] = [
        createUser({ id: 'admin-1' } as any),
      ];

      const roles = new Map<string, string[]>([['admin-1', [globalAdminRoleId]]]);

      // Mock MFA registered
      (users[0] as any).isMfaRegistered = true;

      const result = detectGlobalAdminNoMfa(users, roles, false);

      expect(result.count).toBe(0);
    });

    it('should include affected entities when includeDetails=true', () => {
      const users: AzureUser[] = [createUser({ id: 'admin-1', userPrincipalName: 'admin@example.com' })];
      const roles = new Map<string, string[]>([['admin-1', [globalAdminRoleId]]]);

      const result = detectGlobalAdminNoMfa(users, roles, true);

      expect(result.affectedEntities).toBeDefined();
      expect(result.affectedEntities).toEqual(['admin@example.com']);
    });
  });

  describe('detectPrivilegedUserNoMfa', () => {
    it('should detect privileged user without MFA', () => {
      const securityAdminRoleId = '194ae4cb-b126-40b2-bd5b-6091b380977d';
      const users: AzureUser[] = [createUser({ id: 'sec-admin-1' })];
      const roles = new Map<string, string[]>([['sec-admin-1', [securityAdminRoleId]]]);

      const result = detectPrivilegedUserNoMfa(users, roles, false);

      expect(result.type).toBe('AZURE_PRIVILEGED_USER_NO_MFA');
      expect(result.severity).toBe('critical');
      expect(result.count).toBe(1);
    });
  });

  describe('detectRiskyUserHigh', () => {
    it('should detect high-risk users', () => {
      const users: AzureUser[] = [
        createUser({ id: 'risky-1' } as any),
        createUser({ id: 'safe-1' }),
      ];

      (users[0] as any).riskLevel = 'high';

      const result = detectRiskyUserHigh(users, false);

      expect(result.type).toBe('AZURE_RISKY_USER_HIGH');
      expect(result.severity).toBe('critical');
      expect(result.count).toBe(1);
    });
  });

  describe('detectUserInactive', () => {
    it('should detect inactive users (90+ days)', () => {
      const now = Date.now();
      const ninetyOneDaysAgo = new Date(now - 91 * 24 * 60 * 60 * 1000).toISOString();

      const users: AzureUser[] = [
        createUser({ id: 'inactive-1', lastSignInDateTime: ninetyOneDaysAgo }),
        createUser({ id: 'active-1', lastSignInDateTime: new Date().toISOString() }),
      ];

      const result = detectUserInactive(users, false);

      expect(result.type).toBe('AZURE_USER_INACTIVE');
      expect(result.severity).toBe('high');
      expect(result.count).toBe(1);
    });

    it('should not detect recently active users', () => {
      const users: AzureUser[] = [
        createUser({ lastSignInDateTime: new Date().toISOString() }),
      ];

      const result = detectUserInactive(users, false);

      expect(result.count).toBe(0);
    });
  });

  describe('detectPasswordNeverExpires', () => {
    it('should detect users with password never expires', () => {
      const users: AzureUser[] = [
        createUser({ id: 'user-1' } as any),
        createUser({ id: 'user-2' }),
      ];

      (users[0] as any).passwordPolicies = 'DisablePasswordExpiration';

      const result = detectPasswordNeverExpires(users, false);

      expect(result.type).toBe('AZURE_USER_PASSWORD_NEVER_EXPIRES');
      expect(result.severity).toBe('high');
      expect(result.count).toBe(1);
    });
  });

  describe('detectRiskyUserMedium', () => {
    it('should detect medium-risk users', () => {
      const users: AzureUser[] = [
        createUser({ id: 'risky-1' } as any),
      ];

      (users[0] as any).riskLevel = 'medium';

      const result = detectRiskyUserMedium(users, false);

      expect(result.type).toBe('AZURE_RISKY_USER_MEDIUM');
      expect(result.severity).toBe('high');
      expect(result.count).toBe(1);
    });
  });

  describe('detectPasswordOld', () => {
    it('should detect old passwords (180+ days)', () => {
      const now = Date.now();
      const sixMonthsAgo = new Date(now - 181 * 24 * 60 * 60 * 1000).toISOString();

      const users: AzureUser[] = [
        createUser({ id: 'user-1' } as any),
        createUser({ id: 'user-2' }),
      ];

      (users[0] as any).lastPasswordChangeDateTime = sixMonthsAgo;

      const result = detectPasswordOld(users, false);

      expect(result.type).toBe('AZURE_PASSWORD_OLD');
      expect(result.severity).toBe('medium');
      expect(result.count).toBe(1);
    });
  });

  describe('detectUserNeverSignedIn', () => {
    it('should detect users who never signed in', () => {
      const users: AzureUser[] = [
        createUser({ id: 'user-1', lastSignInDateTime: undefined, accountEnabled: true }),
        createUser({ id: 'user-2', lastSignInDateTime: new Date().toISOString(), accountEnabled: true }),
      ];

      const result = detectUserNeverSignedIn(users, false);

      expect(result.type).toBe('AZURE_USER_NEVER_SIGNED_IN');
      expect(result.severity).toBe('medium');
      expect(result.count).toBe(1);
    });

    it('should not detect disabled users', () => {
      const users: AzureUser[] = [
        createUser({ lastSignInDateTime: undefined, accountEnabled: false }),
      ];

      const result = detectUserNeverSignedIn(users, false);

      expect(result.count).toBe(0);
    });
  });

  describe('detectUserUnlicensed', () => {
    it('should detect unlicensed active users', () => {
      const users: AzureUser[] = [
        createUser({ id: 'user-1', accountEnabled: true } as any),
        createUser({ id: 'user-2', accountEnabled: true } as any),
      ];

      (users[0] as any).assignedLicenses = [];
      (users[1] as any).assignedLicenses = [{ skuId: 'license-1' }];

      const result = detectUserUnlicensed(users, false);

      expect(result.type).toBe('AZURE_USER_UNLICENSED');
      expect(result.severity).toBe('medium');
      expect(result.count).toBe(1);
    });
  });

  describe('detectUserExternalMember', () => {
    it('should detect external users as members', () => {
      const users: AzureUser[] = [
        createUser({ id: 'ext-1', userPrincipalName: 'guest_external.com#EXT#@tenant.onmicrosoft.com' } as any),
        createUser({ id: 'int-1', userPrincipalName: 'internal@tenant.onmicrosoft.com' }),
      ];

      (users[0] as any).userType = 'Member';

      const result = detectUserExternalMember(users, false);

      expect(result.type).toBe('AZURE_USER_EXTERNAL_MEMBER');
      expect(result.severity).toBe('medium');
      expect(result.count).toBe(1);
    });
  });

  describe('detectUserSecurityVulnerabilities', () => {
    it('should detect multiple user vulnerabilities', () => {
      const users: AzureUser[] = [
        createUser({ id: 'admin-1' }),
        createUser({ id: 'inactive-1', lastSignInDateTime: new Date(Date.now() - 100 * 24 * 60 * 60 * 1000).toISOString() }),
      ];

      const roles = new Map<string, string[]>([['admin-1', [globalAdminRoleId]]]);

      const results = detectUserSecurityVulnerabilities(users, roles, false);

      expect(results.length).toBeGreaterThan(0);
      const types = results.map((r) => r.type);
      expect(types).toContain('AZURE_GLOBAL_ADMIN_NO_MFA');
      expect(types).toContain('AZURE_USER_INACTIVE');
    });

    it('should handle empty user list', () => {
      const results = detectUserSecurityVulnerabilities([], new Map(), false);
      expect(results.length).toBe(0);
    });

    it('should filter out findings with count 0', () => {
      const users: AzureUser[] = [
        createUser({ lastSignInDateTime: new Date().toISOString(), accountEnabled: true } as any),
      ];

      (users[0] as any).isMfaRegistered = true;
      (users[0] as any).assignedLicenses = [{ skuId: 'license-1' }];

      const results = detectUserSecurityVulnerabilities(users, new Map(), false);

      results.forEach((finding) => {
        expect(finding.count).toBeGreaterThan(0);
      });
    });
  });
});
