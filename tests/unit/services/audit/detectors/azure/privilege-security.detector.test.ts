/**
 * Unit Tests for Privilege Security Vulnerability Detector
 * Story 1.8: Azure Vulnerability Detection Engine
 *
 * Tests all privilege-related vulnerability detectors (4 types):
 * - AZURE_GUEST_PRIVILEGED_ACCESS
 * - AZURE_SERVICE_ACCOUNT_PRIVILEGED
 * - AZURE_TOO_MANY_GLOBAL_ADMINS
 * - AZURE_GROUP_DYNAMIC_RISKY_RULE
 */

import {
  detectGuestPrivilegedAccess,
  detectServiceAccountPrivileged,
  detectTooManyGlobalAdmins,
  detectGroupDynamicRiskyRule,
  detectPrivilegeSecurityVulnerabilities,
} from '../../../../../../src/services/audit/detectors/azure/privilege-security.detector';
import { AzureUser, AzureGroup } from '../../../../../../src/types/azure.types';

describe('Privilege Security Detectors', () => {
  const createUser = (overrides: Partial<AzureUser> = {}): AzureUser => ({
    id: 'user-123',
    userPrincipalName: 'test@example.com',
    displayName: 'Test User',
    mail: 'test@example.com',
    accountEnabled: true,
    ...overrides,
  });

  const createGroup = (overrides: Partial<AzureGroup> = {}): AzureGroup => ({
    id: 'group-123',
    displayName: 'Test Group',
    mailEnabled: false,
    securityEnabled: true,
    ...overrides,
  });

  const globalAdminRoleId = '62e90394-69f5-4237-9190-012177145e10';
  const securityAdminRoleId = '194ae4cb-b126-40b2-bd5b-6091b380977d';

  describe('detectGuestPrivilegedAccess', () => {
    it('should detect guest users with privileged roles', () => {
      const users: AzureUser[] = [
        createUser({ id: 'guest-1' } as any),
        createUser({ id: 'member-1' }),
      ];

      (users[0] as any).userType = 'Guest';
      (users[1] as any).userType = 'Member';

      const roles = new Map<string, string[]>([
        ['guest-1', [securityAdminRoleId]],
        ['member-1', [securityAdminRoleId]],
      ]);

      const result = detectGuestPrivilegedAccess(users, roles, false);

      expect(result.type).toBe('AZURE_GUEST_PRIVILEGED_ACCESS');
      expect(result.severity).toBe('critical');
      expect(result.category).toBe('privilegedAccess');
      expect(result.count).toBe(1);
    });

    it('should not detect member users with privileged roles', () => {
      const users: AzureUser[] = [
        createUser({ id: 'member-1' } as any),
      ];

      (users[0] as any).userType = 'Member';

      const roles = new Map<string, string[]>([['member-1', [globalAdminRoleId]]]);

      const result = detectGuestPrivilegedAccess(users, roles, false);

      expect(result.count).toBe(0);
    });

    it('should not detect guest users without privileged roles', () => {
      const users: AzureUser[] = [
        createUser({ id: 'guest-1' } as any),
      ];

      (users[0] as any).userType = 'Guest';

      const roles = new Map<string, string[]>([['guest-1', []]]);

      const result = detectGuestPrivilegedAccess(users, roles, false);

      expect(result.count).toBe(0);
    });
  });

  describe('detectServiceAccountPrivileged', () => {
    it('should detect service accounts with privileged roles', () => {
      const users: AzureUser[] = [
        createUser({
          id: 'svc-1',
          userPrincipalName: 'svc-automation@example.com',
          lastSignInDateTime: undefined,
        }),
        createUser({
          id: 'user-1',
          lastSignInDateTime: new Date().toISOString(),
        }),
      ];

      const roles = new Map<string, string[]>([
        ['svc-1', [globalAdminRoleId]],
        ['user-1', [globalAdminRoleId]],
      ]);

      const result = detectServiceAccountPrivileged(users, roles, false);

      expect(result.type).toBe('AZURE_SERVICE_ACCOUNT_PRIVILEGED');
      expect(result.severity).toBe('critical');
      expect(result.count).toBe(1);
    });

    it('should detect service accounts with "service" in name', () => {
      const users: AzureUser[] = [
        createUser({
          id: 'service-1',
          userPrincipalName: 'service-account@example.com',
        }),
      ];

      const roles = new Map<string, string[]>([['service-1', [securityAdminRoleId]]]);

      const result = detectServiceAccountPrivileged(users, roles, false);

      expect(result.count).toBe(1);
    });

    it('should detect application type users with privileged roles', () => {
      const users: AzureUser[] = [
        createUser({ id: 'app-1' } as any),
      ];

      (users[0] as any).userType = 'Application';

      const roles = new Map<string, string[]>([['app-1', [globalAdminRoleId]]]);

      const result = detectServiceAccountPrivileged(users, roles, false);

      expect(result.count).toBe(1);
    });
  });

  describe('detectTooManyGlobalAdmins', () => {
    it('should detect more than 5 Global Admins', () => {
      const users: AzureUser[] = [
        createUser({ id: 'admin-1' }),
        createUser({ id: 'admin-2' }),
        createUser({ id: 'admin-3' }),
        createUser({ id: 'admin-4' }),
        createUser({ id: 'admin-5' }),
        createUser({ id: 'admin-6' }),
      ];

      const roles = new Map<string, string[]>([
        ['admin-1', [globalAdminRoleId]],
        ['admin-2', [globalAdminRoleId]],
        ['admin-3', [globalAdminRoleId]],
        ['admin-4', [globalAdminRoleId]],
        ['admin-5', [globalAdminRoleId]],
        ['admin-6', [globalAdminRoleId]],
      ]);

      const result = detectTooManyGlobalAdmins(users, roles, false);

      expect(result.type).toBe('AZURE_TOO_MANY_GLOBAL_ADMINS');
      expect(result.severity).toBe('high');
      expect(result.count).toBe(1);
      expect(result.description).toContain('6 Global Administrators');
    });

    it('should not detect 5 or fewer Global Admins', () => {
      const users: AzureUser[] = [
        createUser({ id: 'admin-1' }),
        createUser({ id: 'admin-2' }),
        createUser({ id: 'admin-3' }),
      ];

      const roles = new Map<string, string[]>([
        ['admin-1', [globalAdminRoleId]],
        ['admin-2', [globalAdminRoleId]],
        ['admin-3', [globalAdminRoleId]],
      ]);

      const result = detectTooManyGlobalAdmins(users, roles, false);

      expect(result.count).toBe(0);
    });

    it('should include count in affectedEntities when includeDetails=true', () => {
      const users: AzureUser[] = [
        createUser({ id: 'admin-1' }),
        createUser({ id: 'admin-2' }),
        createUser({ id: 'admin-3' }),
        createUser({ id: 'admin-4' }),
        createUser({ id: 'admin-5' }),
        createUser({ id: 'admin-6' }),
        createUser({ id: 'admin-7' }),
      ];

      const roles = new Map<string, string[]>();
      users.forEach((u) => roles.set(u.id, [globalAdminRoleId]));

      const result = detectTooManyGlobalAdmins(users, roles, true);

      expect(result.affectedEntities).toBeDefined();
      expect(result.affectedEntities?.[0]).toContain('7 Global Admins');
    });
  });

  describe('detectGroupDynamicRiskyRule', () => {
    it('should detect groups with overly broad membership rules', () => {
      const groups: AzureGroup[] = [
        createGroup({
          id: 'group-1',
          displayName: 'All Enabled Users',
        } as any),
        createGroup({
          id: 'group-2',
          displayName: 'Specific Group',
        } as any),
      ];

      (groups[0] as any).groupTypes = ['DynamicMembership'];
      (groups[0] as any).membershipRule = 'user.accountEnabled eq true';

      (groups[1] as any).groupTypes = ['DynamicMembership'];
      (groups[1] as any).membershipRule = 'user.department eq "IT"';

      const result = detectGroupDynamicRiskyRule(groups, false);

      expect(result.type).toBe('AZURE_GROUP_DYNAMIC_RISKY_RULE');
      expect(result.severity).toBe('high');
      expect(result.count).toBe(1);
    });

    it('should detect "all members" rule', () => {
      const groups: AzureGroup[] = [
        createGroup({
          id: 'group-1',
        } as any),
      ];

      (groups[0] as any).groupTypes = ['DynamicMembership'];
      (groups[0] as any).membershipRule = 'user.userType eq "Member"';

      const result = detectGroupDynamicRiskyRule(groups, false);

      expect(result.count).toBe(1);
    });

    it('should detect "all guests" rule', () => {
      const groups: AzureGroup[] = [
        createGroup({
          id: 'group-1',
        } as any),
      ];

      (groups[0] as any).groupTypes = ['DynamicMembership'];
      (groups[0] as any).membershipRule = 'user.userType eq "Guest"';

      const result = detectGroupDynamicRiskyRule(groups, false);

      expect(result.count).toBe(1);
    });

    it('should not detect non-dynamic groups', () => {
      const groups: AzureGroup[] = [
        createGroup({
          id: 'group-1',
        } as any),
      ];

      (groups[0] as any).groupTypes = [];
      (groups[0] as any).membershipRule = 'user.accountEnabled eq true';

      const result = detectGroupDynamicRiskyRule(groups, false);

      expect(result.count).toBe(0);
    });

    it('should not detect groups with specific rules', () => {
      const groups: AzureGroup[] = [
        createGroup({
          id: 'group-1',
        } as any),
      ];

      (groups[0] as any).groupTypes = ['DynamicMembership'];
      (groups[0] as any).membershipRule = 'user.department eq "Finance" and user.country eq "US"';

      const result = detectGroupDynamicRiskyRule(groups, false);

      expect(result.count).toBe(0);
    });
  });

  describe('detectPrivilegeSecurityVulnerabilities', () => {
    it('should detect multiple privilege vulnerabilities', () => {
      const users: AzureUser[] = [
        createUser({ id: 'guest-1' } as any),
        createUser({ id: 'svc-1', userPrincipalName: 'svc-account@example.com', lastSignInDateTime: undefined }),
        createUser({ id: 'admin-1' }),
        createUser({ id: 'admin-2' }),
        createUser({ id: 'admin-3' }),
        createUser({ id: 'admin-4' }),
        createUser({ id: 'admin-5' }),
        createUser({ id: 'admin-6' }),
      ];

      (users[0] as any).userType = 'Guest';

      const roles = new Map<string, string[]>([
        ['guest-1', [securityAdminRoleId]],
        ['svc-1', [globalAdminRoleId]],
        ['admin-1', [globalAdminRoleId]],
        ['admin-2', [globalAdminRoleId]],
        ['admin-3', [globalAdminRoleId]],
        ['admin-4', [globalAdminRoleId]],
        ['admin-5', [globalAdminRoleId]],
        ['admin-6', [globalAdminRoleId]],
      ]);

      const groups: AzureGroup[] = [
        createGroup({ id: 'group-1' } as any),
      ];

      (groups[0] as any).groupTypes = ['DynamicMembership'];
      (groups[0] as any).membershipRule = 'user.accountEnabled eq true';

      const results = detectPrivilegeSecurityVulnerabilities(users, groups, roles, false);

      expect(results.length).toBeGreaterThan(0);
      const types = results.map((r) => r.type);
      expect(types).toContain('AZURE_GUEST_PRIVILEGED_ACCESS');
      expect(types).toContain('AZURE_SERVICE_ACCOUNT_PRIVILEGED');
      expect(types).toContain('AZURE_TOO_MANY_GLOBAL_ADMINS');
      expect(types).toContain('AZURE_GROUP_DYNAMIC_RISKY_RULE');
    });

    it('should handle empty inputs', () => {
      const results = detectPrivilegeSecurityVulnerabilities([], [], new Map(), false);
      expect(results.length).toBe(0);
    });

    it('should filter out findings with count 0', () => {
      const users: AzureUser[] = [
        createUser({ id: 'user-1' } as any),
      ];

      (users[0] as any).userType = 'Member';

      const groups: AzureGroup[] = [
        createGroup({ id: 'group-1' } as any),
      ];

      (groups[0] as any).groupTypes = [];

      const roles = new Map<string, string[]>([['user-1', []]]);

      const results = detectPrivilegeSecurityVulnerabilities(users, groups, roles, false);

      results.forEach((finding) => {
        expect(finding.count).toBeGreaterThan(0);
      });
    });
  });
});
