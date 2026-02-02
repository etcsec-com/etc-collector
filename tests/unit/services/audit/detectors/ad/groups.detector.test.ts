/**
 * Unit Tests for Groups Security Vulnerability Detector
 * Story 1.7: AD Vulnerability Detection Engine
 *
 * Tests all group-related vulnerability detectors:
 * - GPO_MODIFY_RIGHTS
 * - DNS_ADMINS_MEMBER
 * - OVERSIZED_GROUP_CRITICAL
 * - OVERSIZED_GROUP_HIGH
 * - OVERSIZED_GROUP
 * - PRE_WINDOWS_2000_ACCESS
 * - DANGEROUS_GROUP_NESTING
 */

import {
  detectGpoModifyRights,
  detectDnsAdminsMember,
  detectPreWindows2000Access,
  detectOversizedGroupCritical,
  detectOversizedGroupHigh,
  detectOversizedGroup,
  detectDangerousGroupNesting,
} from '../../../../../../src/services/audit/detectors/ad/groups.detector';
import { ADUser, ADGroup } from '../../../../../../src/types/ad.types';

describe('Groups Security Detectors', () => {
  const createUser = (overrides: Partial<ADUser> = {}): ADUser => ({
    dn: 'CN=TestUser,DC=example,DC=com',
    sAMAccountName: 'testuser',
    enabled: true,
    userAccountControl: 0,
    ...overrides,
  });

  const createGroup = (overrides: Partial<ADGroup> = {}): ADGroup => ({
    dn: 'CN=TestGroup,DC=example,DC=com',
    sAMAccountName: 'TestGroup',
    member: [],
    ...overrides,
  });

  describe('detectGpoModifyRights', () => {
    it('should detect Group Policy Creator Owners membership', () => {
      const users: ADUser[] = [
        createUser({
          sAMAccountName: 'gpouser',
          memberOf: ['CN=Group Policy Creator Owners,DC=example,DC=com'],
        }),
        createUser({
          sAMAccountName: 'normaluser',
          memberOf: ['CN=Users,DC=example,DC=com'],
        }),
      ];

      const result = detectGpoModifyRights(users, false);

      expect(result.type).toBe('GPO_MODIFY_RIGHTS');
      expect(result.severity).toBe('high');
      expect(result.category).toBe('groups');
      expect(result.count).toBe(1);
    });
  });

  describe('detectDnsAdminsMember', () => {
    it('should detect DnsAdmins membership', () => {
      const users: ADUser[] = [
        createUser({
          sAMAccountName: 'dnsadmin',
          memberOf: ['CN=DnsAdmins,DC=example,DC=com'],
        }),
        createUser({
          sAMAccountName: 'normaluser',
          memberOf: ['CN=Users,DC=example,DC=com'],
        }),
      ];

      const result = detectDnsAdminsMember(users, false);

      expect(result.type).toBe('DNS_ADMINS_MEMBER');
      expect(result.severity).toBe('high');
      expect(result.count).toBe(1);
    });
  });

  describe('detectPreWindows2000Access', () => {
    it('should detect Pre-Windows 2000 Compatible Access membership', () => {
      const users: ADUser[] = [
        createUser({
          sAMAccountName: 'olduser',
          memberOf: ['CN=Pre-Windows 2000 Compatible Access,DC=example,DC=com'],
        }),
        createUser({
          sAMAccountName: 'normaluser',
          memberOf: [],
        }),
      ];

      const result = detectPreWindows2000Access(users, false);

      expect(result.type).toBe('PRE_WINDOWS_2000_ACCESS');
      expect(result.severity).toBe('medium');
      expect(result.count).toBe(1);
    });
  });

  describe('detectOversizedGroupCritical', () => {
    it('should detect groups with 1000+ members', () => {
      const groups: ADGroup[] = [
        createGroup({
          name: 'HugeGroup',
          member: Array(1500).fill('CN=User,DC=example,DC=com'),
        }),
        createGroup({
          name: 'LargeGroup',
          member: Array(800).fill('CN=User,DC=example,DC=com'),
        }),
        createGroup({
          name: 'SmallGroup',
          member: Array(50).fill('CN=User,DC=example,DC=com'),
        }),
      ];

      const result = detectOversizedGroupCritical(groups, false);

      expect(result.type).toBe('OVERSIZED_GROUP_CRITICAL');
      expect(result.severity).toBe('high');
      expect(result.count).toBe(1); // Only HugeGroup
    });

    it('should handle groups without members', () => {
      const groups: ADGroup[] = [
        createGroup({ name: 'EmptyGroup', member: undefined }),
      ];

      const result = detectOversizedGroupCritical(groups, false);
      expect(result.count).toBe(0);
    });
  });

  describe('detectOversizedGroupHigh', () => {
    it('should detect groups with 500-1000 members', () => {
      const groups: ADGroup[] = [
        createGroup({
          name: 'Group1',
          member: Array(600).fill('CN=User,DC=example,DC=com'),
        }),
        createGroup({
          name: 'Group2',
          member: Array(999).fill('CN=User,DC=example,DC=com'),
        }),
        createGroup({
          name: 'Group3',
          member: Array(1001).fill('CN=User,DC=example,DC=com'), // Too big
        }),
        createGroup({
          name: 'Group4',
          member: Array(400).fill('CN=User,DC=example,DC=com'), // Too small
        }),
      ];

      const result = detectOversizedGroupHigh(groups, false);

      expect(result.type).toBe('OVERSIZED_GROUP_HIGH');
      expect(result.severity).toBe('medium');
      expect(result.count).toBe(2); // Group1 and Group2
    });
  });

  describe('detectOversizedGroup', () => {
    it('should detect groups with 100-500 members', () => {
      const groups: ADGroup[] = [
        createGroup({
          name: 'Group1',
          member: Array(150).fill('CN=User,DC=example,DC=com'),
        }),
        createGroup({
          name: 'Group2',
          member: Array(499).fill('CN=User,DC=example,DC=com'),
        }),
        createGroup({
          name: 'Group3',
          member: Array(501).fill('CN=User,DC=example,DC=com'), // Too big
        }),
        createGroup({
          name: 'Group4',
          member: Array(99).fill('CN=User,DC=example,DC=com'), // Too small
        }),
      ];

      const result = detectOversizedGroup(groups, false);

      expect(result.type).toBe('OVERSIZED_GROUP');
      expect(result.severity).toBe('medium');
      expect(result.count).toBe(2); // Group1 and Group2
    });
  });

  describe('detectDangerousGroupNesting', () => {
    it('should detect protected groups nested in non-protected groups', () => {
      const groups: ADGroup[] = [
        createGroup({
          dn: 'CN=Domain Admins,DC=example,DC=com',
          name: 'Domain Admins',
          memberOf: [
            'CN=IT Department,DC=example,DC=com', // Non-protected group
          ],
        }),
        createGroup({
          dn: 'CN=Enterprise Admins,DC=example,DC=com',
          name: 'Enterprise Admins',
          memberOf: [
            'CN=Administrators,DC=example,DC=com', // Protected group - OK
          ],
        }),
        createGroup({
          dn: 'CN=Regular Users,DC=example,DC=com',
          name: 'Regular Users',
          memberOf: ['CN=All Users,DC=example,DC=com'], // Not a protected group
        }),
      ];

      const result = detectDangerousGroupNesting(groups, false);

      expect(result.type).toBe('DANGEROUS_GROUP_NESTING');
      expect(result.severity).toBe('medium');
      expect(result.count).toBe(1); // Only Domain Admins nested in IT Department
    });

    it('should not flag protected groups nested in other protected groups', () => {
      const groups: ADGroup[] = [
        createGroup({
          dn: 'CN=Domain Admins,DC=example,DC=com',
          name: 'Domain Admins',
          memberOf: [
            'CN=Administrators,DC=example,DC=com',
            'CN=Enterprise Admins,DC=example,DC=com',
          ],
        }),
      ];

      const result = detectDangerousGroupNesting(groups, false);
      expect(result.count).toBe(0);
    });
  });

  describe('Integration Tests', () => {
    it('should detect multiple group vulnerabilities', () => {
      const users: ADUser[] = [
        createUser({
          sAMAccountName: 'poweruser',
          memberOf: [
            'CN=Group Policy Creator Owners,DC=example,DC=com',
            'CN=DnsAdmins,DC=example,DC=com',
          ],
        }),
      ];

      const gpo = detectGpoModifyRights(users, false);
      const dns = detectDnsAdminsMember(users, false);

      expect(gpo.count).toBe(1);
      expect(dns.count).toBe(1);
    });

    it('should handle empty lists', () => {
      const emptyUsers: ADUser[] = [];
      const emptyGroups: ADGroup[] = [];

      const gpo = detectGpoModifyRights(emptyUsers, false);
      const oversized = detectOversizedGroupCritical(emptyGroups, false);

      expect(gpo.count).toBe(0);
      expect(oversized.count).toBe(0);
    });
  });
});
