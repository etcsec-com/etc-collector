/**
 * Basic Azure Provider Integration Tests
 *
 * These tests require a real Azure AD tenant with configured application.
 * To run these tests, set the following environment variables:
 *
 * TEST_AZURE_TENANT_ID=your-tenant-id
 * TEST_AZURE_CLIENT_ID=your-client-id
 * TEST_AZURE_CLIENT_SECRET=your-client-secret
 *
 * Tests are SKIPPED by default if these variables are not set.
 */

import { GraphProvider } from '../../../src/providers/azure/graph.provider';
import { AzureConfig } from '../../../src/types/config.types';

// Read config from environment variables
const TEST_AZURE_CONFIG: AzureConfig | null = process.env['TEST_AZURE_TENANT_ID']
  ? {
      tenantId: process.env['TEST_AZURE_TENANT_ID'],
      clientId: process.env['TEST_AZURE_CLIENT_ID'] || '',
      clientSecret: process.env['TEST_AZURE_CLIENT_SECRET'] || '',
    }
  : null;

// Skip tests if Azure config not provided
const describeIntegration = TEST_AZURE_CONFIG ? describe : describe.skip;

describeIntegration('Azure Provider Basic Integration', () => {
  let provider: GraphProvider;

  beforeAll(() => {
    if (!TEST_AZURE_CONFIG) {
      throw new Error('TEST_AZURE_CONFIG not set');
    }
    provider = new GraphProvider(TEST_AZURE_CONFIG);
  });

  afterAll(async () => {
    try {
      await provider.disconnect();
    } catch (error) {
      // Ignore disconnect errors in cleanup
    }
  });

  it('AZ1: should authenticate with Microsoft Graph', async () => {
    await expect(provider.authenticate()).resolves.not.toThrow();
  }, 30000);

  it('AZ2: should test connection successfully', async () => {
    const result = await provider.testConnection();

    expect(result.success).toBe(true);
    expect(result.message).toBe('Connection successful');
    expect(result.details?.tenantId).toBe(TEST_AZURE_CONFIG?.tenantId);
    expect(result.details?.authenticated).toBe(true);
    expect(result.details?.responseTime).toBeGreaterThan(0);
  }, 30000);

  it('AZ3: should get Azure AD users', async () => {
    await provider.authenticate();
    const users = await provider.getUsers();

    expect(Array.isArray(users)).toBe(true);
    expect(users.length).toBeGreaterThan(0);

    const firstUser = users[0];
    expect(firstUser?.id).toBeDefined();
    expect(firstUser?.userPrincipalName).toBeDefined();
    expect(typeof firstUser?.accountEnabled).toBe('boolean');
  }, 30000);

  it('AZ4: should get Azure AD users with filter', async () => {
    // Get only enabled users
    const users = await provider.getUsers({
      filter: 'accountEnabled eq true',
    });

    expect(Array.isArray(users)).toBe(true);

    // Verify all returned users are enabled
    if (users.length > 0) {
      users.forEach((user) => {
        expect(user.accountEnabled).toBe(true);
      });
    }
  }, 30000);

  it('AZ5: should get Azure AD users with select', async () => {
    const users = await provider.getUsers({
      select: ['id', 'userPrincipalName', 'displayName'],
      top: 5,
    });

    expect(Array.isArray(users)).toBe(true);
    expect(users.length).toBeGreaterThan(0);
    expect(users.length).toBeLessThanOrEqual(5);

    const firstUser = users[0];
    expect(firstUser?.id).toBeDefined();
    expect(firstUser?.userPrincipalName).toBeDefined();
  }, 30000);

  it('AZ6: should get Azure AD groups', async () => {
    const groups = await provider.getGroups();

    expect(Array.isArray(groups)).toBe(true);
    expect(groups.length).toBeGreaterThan(0);

    const firstGroup = groups[0];
    expect(firstGroup?.id).toBeDefined();
    expect(firstGroup?.displayName).toBeDefined();
    expect(typeof firstGroup?.securityEnabled).toBe('boolean');
  }, 30000);

  it('AZ7: should get security groups only', async () => {
    const groups = await provider.getGroups({
      filter: 'securityEnabled eq true',
    });

    expect(Array.isArray(groups)).toBe(true);

    // Verify all returned groups are security groups
    if (groups.length > 0) {
      groups.forEach((group) => {
        expect(group.securityEnabled).toBe(true);
      });
    }
  }, 30000);

  it('AZ8: should get Azure AD applications', async () => {
    const apps = await provider.getApplications();

    expect(Array.isArray(apps)).toBe(true);
    // May have 0 applications in test tenant

    if (apps.length > 0) {
      const firstApp = apps[0];
      expect(firstApp?.id).toBeDefined();
      expect(firstApp?.appId).toBeDefined();
      expect(firstApp?.displayName).toBeDefined();
    }
  }, 30000);

  it('AZ9: should handle pagination automatically', async () => {
    // Request all users (tests pagination internally)
    const users = await provider.getUsers();

    expect(Array.isArray(users)).toBe(true);
    // Just verify it completes without error
  }, 60000); // Longer timeout for pagination

  it('AZ10: should handle invalid credentials', async () => {
    if (!TEST_AZURE_CONFIG) {
      throw new Error('TEST_AZURE_CONFIG not set');
    }

    const badConfig: AzureConfig = {
      ...TEST_AZURE_CONFIG,
      clientSecret: 'wrong-secret',
    };

    const badProvider = new GraphProvider(badConfig);
    await expect(badProvider.authenticate()).rejects.toThrow();
  }, 30000);
});
