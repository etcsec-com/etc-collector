import { LDAPProvider } from '../../../src/providers/ldap/ldap.provider';
import { LDAPConfig } from '../../../src/types/config.types';

/**
 * LDAP Provider Integration Tests (Comprehensive)
 * Task 9: Write Integration Tests for LDAP Provider (Story 1.5)
 *
 * These tests require a real Active Directory server.
 * To run these tests, set the following environment variables:
 *
 * TEST_LDAP_URL=ldaps://your-dc:636
 * TEST_LDAP_BIND_DN=CN=service-user,CN=Users,DC=domain,DC=com
 * TEST_LDAP_BIND_PASSWORD=password
 * TEST_LDAP_BASE_DN=DC=domain,DC=com
 * TEST_LDAP_TLS_VERIFY=false
 *
 * Tests are SKIPPED by default if these variables are not set.
 */

// Configuration for test AD
const TEST_LDAP_CONFIG: LDAPConfig | null = process.env['TEST_LDAP_URL']
  ? {
      url: process.env['TEST_LDAP_URL'],
      bindDN: process.env['TEST_LDAP_BIND_DN'] || '',
      bindPassword: process.env['TEST_LDAP_BIND_PASSWORD'] || '',
      baseDN: process.env['TEST_LDAP_BASE_DN'] || '',
      tlsVerify: process.env['TEST_LDAP_TLS_VERIFY'] === 'true',
      timeout: 10000,
    }
  : null;

// Skip these tests if LDAP config not provided
const describeIntegration = TEST_LDAP_CONFIG ? describe : describe.skip;

describeIntegration('LDAP Provider Integration Tests', () => {
  let provider: LDAPProvider;

  beforeAll(() => {
    if (!TEST_LDAP_CONFIG) {
      throw new Error('TEST_LDAP_CONFIG not set');
    }
    provider = new LDAPProvider(TEST_LDAP_CONFIG);
  });

  afterAll(async () => {
    await provider.disconnect();
  });

  describe('Connection Tests', () => {
    it('should connect to LDAPS server', async () => {
      await expect(provider.connect()).resolves.not.toThrow();
    }, 15000);

    it('should test connection successfully', async () => {
      const result = await provider.testConnection();

      expect(result.success).toBe(true);
      expect(result.message).toBe('Connection successful');
      expect(result.details).toBeDefined();
      expect(result.details?.protocol).toBe('ldaps');
      expect(result.details?.url).toBe('ldaps://10.10.0.83:636');
      expect(result.details?.baseDN).toBe('DC=aza-me,DC=cc');
      expect(result.details?.responseTime).toBeGreaterThan(0);
    }, 15000);

    it('should handle disconnect gracefully', async () => {
      await expect(provider.disconnect()).resolves.not.toThrow();
    }, 10000);

    it('should reconnect after disconnect', async () => {
      await provider.disconnect();
      await provider.connect();

      const result = await provider.testConnection();
      expect(result.success).toBe(true);
    }, 15000);
  });

  describe('User Search Tests', () => {
    beforeEach(async () => {
      await provider.connect();
    });

    it('should search for all users', async () => {
      const users = await provider.searchUsers();

      expect(Array.isArray(users)).toBe(true);
      expect(users.length).toBeGreaterThan(0);

      // Verify user structure
      const firstUser = users[0];
      expect(firstUser).toBeDefined();
      expect(firstUser?.dn).toBeDefined();
      expect(firstUser?.sAMAccountName).toBeDefined();
      expect(typeof firstUser?.enabled).toBe('boolean');
    }, 20000);

    it('should search for specific user by sAMAccountName', async () => {
      // Search for n8n Service user
      const users = await provider.searchUsers('(sAMAccountName=n8n Service)');

      expect(users.length).toBeGreaterThanOrEqual(1);

      const n8nUser = users.find((u) => u.sAMAccountName === 'n8n Service');
      expect(n8nUser).toBeDefined();
      expect(n8nUser?.dn).toContain('CN=n8n Service');
    }, 20000);

    it('should search with custom attributes', async () => {
      const users = await provider.searchUsers(undefined, ['dn', 'sAMAccountName', 'mail']);

      expect(users.length).toBeGreaterThan(0);

      const firstUser = users[0];
      expect(firstUser?.dn).toBeDefined();
      expect(firstUser?.sAMAccountName).toBeDefined();
    }, 20000);

    it('should handle user with memberOf groups', async () => {
      const users = await provider.searchUsers();

      // Find a user with group memberships
      const userWithGroups = users.find((u) => u.memberOf && u.memberOf.length > 0);

      if (userWithGroups) {
        expect(Array.isArray(userWithGroups.memberOf)).toBe(true);
        expect(userWithGroups.memberOf!.length).toBeGreaterThan(0);
        expect(userWithGroups.memberOf![0]).toContain('CN=');
      }
    }, 20000);
  });

  describe('Group Search Tests', () => {
    beforeEach(async () => {
      await provider.connect();
    });

    it('should search for all groups', async () => {
      const groups = await provider.searchGroups();

      expect(Array.isArray(groups)).toBe(true);
      expect(groups.length).toBeGreaterThan(0);

      // Verify group structure
      const firstGroup = groups[0];
      expect(firstGroup).toBeDefined();
      expect(firstGroup?.dn).toBeDefined();
      expect(firstGroup?.sAMAccountName).toBeDefined();
    }, 20000);

    it('should search for specific group', async () => {
      // Search for built-in groups (Domain Admins, Domain Users, etc.)
      const groups = await provider.searchGroups('(sAMAccountName=Domain Users)');

      expect(groups.length).toBeGreaterThanOrEqual(1);

      const domainUsers = groups.find((g) => g.sAMAccountName === 'Domain Users');
      expect(domainUsers).toBeDefined();
      expect(domainUsers?.dn).toContain('CN=Domain Users');
    }, 20000);

    it('should retrieve group members', async () => {
      const groups = await provider.searchGroups();

      // Find a group with members
      const groupWithMembers = groups.find((g) => g.member && g.member.length > 0);

      if (groupWithMembers) {
        expect(Array.isArray(groupWithMembers.member)).toBe(true);
        expect(groupWithMembers.member!.length).toBeGreaterThan(0);
        expect(groupWithMembers.member![0]).toContain('CN=');
      }
    }, 20000);
  });

  describe('Computer Search Tests', () => {
    beforeEach(async () => {
      await provider.connect();
    });

    it('should search for computers', async () => {
      const computers = await provider.searchComputers();

      expect(Array.isArray(computers)).toBe(true);

      // May have 0 computers in test environment
      if (computers.length > 0) {
        const firstComputer = computers[0];
        expect(firstComputer?.dn).toBeDefined();
        expect(firstComputer?.sAMAccountName).toBeDefined();
        expect(typeof firstComputer?.enabled).toBe('boolean');
      }
    }, 20000);
  });

  describe('OU Search Tests', () => {
    beforeEach(async () => {
      await provider.connect();
    });

    it('should search for organizational units', async () => {
      const ous = await provider.searchOUs();

      expect(Array.isArray(ous)).toBe(true);
      expect(ous.length).toBeGreaterThan(0);

      // Verify OU structure
      const firstOU = ous[0];
      expect(firstOU).toBeDefined();
      expect(firstOU?.dn).toBeDefined();
      expect(firstOU?.name).toBeDefined();
    }, 20000);

    it('should find Users OU', async () => {
      const ous = await provider.searchOUs('(name=Users)');

      expect(ous.length).toBeGreaterThanOrEqual(1);

      const usersOU = ous.find((ou) => ou.name === 'Users');
      expect(usersOU).toBeDefined();
      expect(usersOU?.dn).toContain('OU=Users');
    }, 20000);
  });

  describe('Generic Search Tests', () => {
    beforeEach(async () => {
      await provider.connect();
    });

    it('should perform generic search for domain object', async () => {
      const results = await provider.search('DC=aza-me,DC=cc', {
        filter: '(objectClass=domain)',
        scope: 'base',
      });

      expect(results.length).toBe(1);
      expect(results[0]).toBeDefined();
    }, 20000);

    it('should search with subtree scope', async () => {
      const results = await provider.search('DC=aza-me,DC=cc', {
        filter: '(objectClass=organizationalUnit)',
        scope: 'sub',
        sizeLimit: 10,
      });

      expect(Array.isArray(results)).toBe(true);
      expect(results.length).toBeGreaterThan(0);
      expect(results.length).toBeLessThanOrEqual(10);
    }, 20000);
  });

  describe('Filter Builder Tests', () => {
    beforeEach(async () => {
      await provider.connect();
    });

    it('should use safe filter builder to prevent injection', async () => {
      // Build safe filter with potentially malicious input
      const maliciousInput = '*)(objectClass=*)';
      const safeFilter = provider.buildSafeFilter('sAMAccountName', '=', maliciousInput);

      // Should escape special characters
      expect(safeFilter).toBe('(sAMAccountName=\\2a\\29\\28objectClass=\\2a\\29)');

      // Search should work without injection
      const users = await provider.searchUsers(safeFilter);

      // Should return 0 results (no user with that literal name)
      expect(users.length).toBe(0);
    }, 20000);

    it('should build logical AND filter', async () => {
      const filter = provider.buildLogicalFilter('&', [
        '(objectClass=user)',
        '(objectCategory=person)',
        '(!(userAccountControl:1.2.840.113556.1.4.803:=2))', // Not disabled
      ]);

      expect(filter).toContain('(&');

      // Use the built filter
      const users = await provider.searchUsers(filter);
      expect(Array.isArray(users)).toBe(true);
    }, 20000);
  });

  describe('Error Handling Tests', () => {
    it('should handle invalid credentials gracefully', async () => {
      const badConfig: LDAPConfig = {
        ...TEST_LDAP_CONFIG,
        bindPassword: 'wrong-password',
      };

      const badProvider = new LDAPProvider(badConfig);

      await expect(badProvider.connect()).rejects.toThrow();
    }, 15000);

    it('should handle invalid base DN', async () => {
      await provider.connect();

      await expect(
        provider.search('DC=invalid,DC=domain', {
          filter: '(objectClass=*)',
          scope: 'sub',
        })
      ).rejects.toThrow();
    }, 15000);

    it('should validate filter syntax', async () => {
      await provider.connect();

      await expect(
        provider.search('DC=aza-me,DC=cc', {
          filter: 'invalid-filter-syntax',
          scope: 'sub',
        })
      ).rejects.toThrow('Invalid LDAP filter syntax');
    }, 10000);
  });

  describe('Performance Tests', () => {
    beforeEach(async () => {
      await provider.connect();
    });

    it('should complete search within reasonable time', async () => {
      const startTime = Date.now();

      await provider.searchUsers();

      const elapsed = Date.now() - startTime;

      // Should complete within 10 seconds
      expect(elapsed).toBeLessThan(10000);
    }, 15000);

    it('should handle paged results for large datasets', async () => {
      // Search all users with paging enabled (default)
      const users = await provider.searchUsers();

      expect(Array.isArray(users)).toBe(true);
      // Just verify it completes without error
    }, 30000);
  });
});
