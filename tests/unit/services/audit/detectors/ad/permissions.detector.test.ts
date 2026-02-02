/**
 * Unit Tests for Permissions Security Vulnerability Detector
 * Story 1.7: AD Vulnerability Detection Engine
 *
 * Tests all ACL/permissions-related vulnerability detectors:
 * - ACL_GENERICALL
 * - ACL_WRITEDACL
 * - ACL_WRITEOWNER
 * - ACL_GENERICWRITE
 * - ACL_FORCECHANGEPASSWORD
 * - EVERYONE_IN_ACL
 * - WRITESPN_ABUSE
 * - GPO_LINK_POISONING
 * - ADMINSDHOLDER_BACKDOOR
 */

import {
  detectAclGenericAll,
  detectAclWriteDacl,
  detectAclWriteOwner,
  detectAclGenericWrite,
  detectAclForceChangePassword,
  detectEveryoneInAcl,
  detectWriteSpnAbuse,
  detectGpoLinkPoisoning,
  detectAdminSdHolderBackdoor,
} from '../../../../../../src/services/audit/detectors/ad/permissions.detector';
import { AclEntry } from '../../../../../../src/types/ad.types';

describe('Permissions Security Detectors', () => {
  const createAclEntry = (overrides: Partial<AclEntry> = {}): AclEntry => ({
    objectDn: 'CN=TestUser,DC=example,DC=com',
    trustee: 'S-1-5-21-1234567890-1234567890-1234567890-1001',
    accessMask: 0,
    aceType: 'ACCESS_ALLOWED_ACE_TYPE',
    ...overrides,
  });

  describe('detectAclGenericAll', () => {
    it('should detect GenericAll permissions', () => {
      const aclEntries: AclEntry[] = [
        createAclEntry({
          accessMask: 0x10000000, // GENERIC_ALL
        }),
        createAclEntry({ accessMask: 0x00 }),
      ];

      const result = detectAclGenericAll(aclEntries, false);

      expect(result.type).toBe('ACL_GENERICALL');
      expect(result.severity).toBe('high');
      expect(result.category).toBe('permissions');
      expect(result.count).toBe(1);
    });
  });

  describe('detectAclWriteDacl', () => {
    it('should detect WriteDACL permissions', () => {
      const aclEntries: AclEntry[] = [
        createAclEntry({
          accessMask: 0x00040000, // WRITE_DACL
        }),
        createAclEntry({ accessMask: 0x00 }),
      ];

      const result = detectAclWriteDacl(aclEntries, false);

      expect(result.type).toBe('ACL_WRITEDACL');
      expect(result.severity).toBe('high');
      expect(result.count).toBe(1);
    });
  });

  describe('detectAclWriteOwner', () => {
    it('should detect WriteOwner permissions', () => {
      const aclEntries: AclEntry[] = [
        createAclEntry({
          accessMask: 0x00080000, // WRITE_OWNER
        }),
        createAclEntry({ accessMask: 0x00 }),
      ];

      const result = detectAclWriteOwner(aclEntries, false);

      expect(result.type).toBe('ACL_WRITEOWNER');
      expect(result.severity).toBe('high');
      expect(result.count).toBe(1);
    });
  });

  describe('detectAclGenericWrite', () => {
    it('should detect GenericWrite permissions', () => {
      const aclEntries: AclEntry[] = [
        createAclEntry({
          accessMask: 0x40000000, // GENERIC_WRITE
        }),
        createAclEntry({ accessMask: 0x00 }),
      ];

      const result = detectAclGenericWrite(aclEntries, false);

      expect(result.type).toBe('ACL_GENERICWRITE');
      expect(result.severity).toBe('medium');
      expect(result.count).toBe(1);
    });
  });

  describe('detectAclForceChangePassword', () => {
    it('should detect ForceChangePassword permissions', () => {
      const aclEntries: AclEntry[] = [
        createAclEntry({
          objectType: '00299570-246d-11d0-a768-00aa006e0529', // User-Force-Change-Password
        }),
        createAclEntry({ accessMask: 0x00 }),
      ];

      const result = detectAclForceChangePassword(aclEntries, false);

      expect(result.type).toBe('ACL_FORCECHANGEPASSWORD');
      expect(result.severity).toBe('medium');
      expect(result.count).toBe(1);
    });
  });

  describe('detectEveryoneInAcl', () => {
    it('should detect Everyone group with write permissions', () => {
      const aclEntries: AclEntry[] = [
        createAclEntry({
          trustee: 'S-1-1-0', // Everyone
          accessMask: 0x00020000, // WRITE_PROP
        }),
        createAclEntry({
          trustee: 'S-1-5-11', // Authenticated Users
          accessMask: 0x00020000,
        }),
        createAclEntry({
          trustee: 'S-1-1-0', // Everyone but no write
          accessMask: 0x00000001,
        }),
      ];

      const result = detectEveryoneInAcl(aclEntries, false);

      expect(result.type).toBe('EVERYONE_IN_ACL');
      expect(result.severity).toBe('medium');
      expect(result.count).toBe(2); // Everyone + Authenticated Users with write
    });
  });

  describe('detectWriteSpnAbuse', () => {
    it('should detect WriteSPN permissions', () => {
      const aclEntries: AclEntry[] = [
        createAclEntry({
          objectType: 'f3a64788-5306-11d1-a9c5-0000f80367c1', // Service-Principal-Name
        }),
        createAclEntry({ accessMask: 0x00 }),
      ];

      const result = detectWriteSpnAbuse(aclEntries, false);

      expect(result.type).toBe('WRITESPN_ABUSE');
      expect(result.severity).toBe('medium');
      expect(result.count).toBe(1);
    });
  });

  describe('detectGpoLinkPoisoning', () => {
    it('should detect GPO weak ACLs', () => {
      const aclEntries: AclEntry[] = [
        createAclEntry({
          objectDn: 'CN=TestGPO,CN=Policies,CN=System,DC=example,DC=com',
          accessMask: 0x10000000, // GENERIC_ALL
        }),
        createAclEntry({ objectDn: 'CN=User,DC=example,DC=com' }),
      ];

      const result = detectGpoLinkPoisoning(aclEntries, false);

      expect(result.type).toBe('GPO_LINK_POISONING');
      expect(result.severity).toBe('medium');
      expect(result.count).toBe(1);
    });
  });

  describe('detectAdminSdHolderBackdoor', () => {
    it('should detect AdminSDHolder ACL modifications', () => {
      const aclEntries: AclEntry[] = [
        createAclEntry({
          objectDn: 'CN=AdminSDHolder,CN=System,DC=example,DC=com',
          accessMask: 0x00040000, // WRITE_DACL
        }),
        createAclEntry({ objectDn: 'CN=User,DC=example,DC=com' }),
      ];

      const result = detectAdminSdHolderBackdoor(aclEntries, false);

      expect(result.type).toBe('ADMINSDHOLDER_BACKDOOR');
      expect(result.severity).toBe('medium');
      expect(result.count).toBe(1);
    });
  });

  describe('Integration Tests', () => {
    it('should detect multiple ACL vulnerabilities', () => {
      const aclEntries: AclEntry[] = [
        createAclEntry({
          objectDn: 'CN=User1,DC=example,DC=com',
          accessMask: 0x10000000, // GENERIC_ALL
        }),
        createAclEntry({
          objectDn: 'CN=User1,DC=example,DC=com',
          trustee: 'S-1-1-0', // Everyone
          accessMask: 0x00020000, // WRITE_PROP
        }),
      ];

      const genericAll = detectAclGenericAll(aclEntries, false);
      const everyone = detectEveryoneInAcl(aclEntries, false);

      expect(genericAll.count).toBe(1);
      expect(everyone.count).toBe(1);
    });

    it('should handle empty ACL list', () => {
      const result = detectAclGenericAll([], false);
      expect(result.count).toBe(0);
    });

    it('should include affected entities when includeDetails=true', () => {
      const aclEntries: AclEntry[] = [
        createAclEntry({
          objectDn: 'CN=VulnUser,DC=example,DC=com',
          accessMask: 0x10000000,
        }),
      ];

      const result = detectAclGenericAll(aclEntries, true);

      expect(result.affectedEntities).toBeDefined();
      expect(result.affectedEntities).toHaveLength(1);
      expect(result.affectedEntities?.[0]).toContain('VulnUser');
    });
  });
});
