/**
 * Graph Provider Unit Tests
 *
 * Tests for Microsoft Graph provider implementation.
 */

import { GraphProvider } from '../../../../src/providers/azure/graph.provider';
import { GraphClient } from '../../../../src/providers/azure/graph-client';
import { AzureProviderConfig } from '../../../../src/types/config.types';
import {
  AzureAPIError,
  AzureAuthenticationError,
  AzurePermissionError,
} from '../../../../src/providers/azure/azure-errors';
import { AzureUser, AzureGroup, AzureApp, AzurePolicy } from '../../../../src/types/azure.types';

// Mock GraphClient
jest.mock('../../../../src/providers/azure/graph-client');

describe('GraphProvider', () => {
  let provider: GraphProvider;
  let mockClient: jest.Mocked<GraphClient>;
  const mockConfig: AzureProviderConfig = {
    tenantId: 'tenant-123',
    clientId: 'client-456',
    clientSecret: 'secret-789',
  };

  beforeEach(() => {
    jest.clearAllMocks();

    // Create mock client instance
    mockClient = {
      authenticate: jest.fn().mockResolvedValue(undefined),
      get: jest.fn(),
      getAll: jest.fn(),
      testConnection: jest.fn(),
      disconnect: jest.fn(),
      getAccessToken: jest.fn(),
    } as unknown as jest.Mocked<GraphClient>;

    // Mock the GraphClient constructor to return our mock
    (GraphClient as jest.MockedClass<typeof GraphClient>).mockImplementation(() => mockClient);

    provider = new GraphProvider(mockConfig);
  });

  describe('authenticate', () => {
    it('should authenticate with Graph API', async () => {
      await provider.authenticate();

      expect(mockClient.authenticate).toHaveBeenCalledTimes(1);
    });

    it('should throw error if authentication fails', async () => {
      mockClient.authenticate.mockRejectedValue(
        new AzureAuthenticationError('Auth failed', 'tenant', 'client')
      );

      await expect(provider.authenticate()).rejects.toThrow(AzureAuthenticationError);
    });
  });

  describe('testConnection', () => {
    it('should return success on successful connection', async () => {
      mockClient.get.mockResolvedValue({ value: [{ id: 'org-123' }] });

      const result = await provider.testConnection();

      expect(result.success).toBe(true);
      expect(result.message).toBe('Connection successful');
      expect(result.details).toMatchObject({
        tenantId: mockConfig.tenantId,
        clientId: mockConfig.clientId,
        authenticated: true,
      });
      expect(result.details?.responseTime).toBeGreaterThanOrEqual(0);
    });

    it('should return failure on authentication error', async () => {
      mockClient.authenticate.mockRejectedValue(
        new AzureAuthenticationError('Invalid credentials', 'tenant', 'client')
      );

      const result = await provider.testConnection();

      expect(result.success).toBe(false);
      expect(result.message).toContain('Authentication failed');
      expect(result.details?.authenticated).toBe(false);
    });

    it('should return failure on API error', async () => {
      mockClient.get.mockRejectedValue(new AzureAPIError('API error', '/organization', 500));

      const result = await provider.testConnection();

      expect(result.success).toBe(false);
      expect(result.message).toContain('Connection test failed');
    });
  });

  describe('getUsers', () => {
    const mockUsers: AzureUser[] = [
      {
        id: 'user-1',
        userPrincipalName: 'user1@example.com',
        displayName: 'User One',
        accountEnabled: true,
      },
      {
        id: 'user-2',
        userPrincipalName: 'user2@example.com',
        displayName: 'User Two',
        accountEnabled: false,
      },
    ];

    it('should get all users without options', async () => {
      mockClient.getAll.mockResolvedValue(mockUsers);

      const users = await provider.getUsers();

      expect(mockClient.getAll).toHaveBeenCalledWith('/users', undefined);
      expect(users).toEqual(mockUsers);
    });

    it('should get users with filter', async () => {
      mockClient.getAll.mockResolvedValue([mockUsers[0]]);

      const users = await provider.getUsers({
        filter: "startsWith(displayName, 'User One')",
      });

      expect(mockClient.getAll).toHaveBeenCalledWith('/users', {
        '$filter': "startsWith(displayName, 'User One')",
      });
      expect(users).toHaveLength(1);
    });

    it('should get users with select', async () => {
      mockClient.getAll.mockResolvedValue(mockUsers);

      await provider.getUsers({
        select: ['id', 'userPrincipalName', 'displayName'],
      });

      expect(mockClient.getAll).toHaveBeenCalledWith('/users', {
        '$select': 'id,userPrincipalName,displayName',
      });
    });

    it('should get users with top and skip', async () => {
      mockClient.getAll.mockResolvedValue([mockUsers[0]]);

      await provider.getUsers({ top: 1, skip: 1 });

      expect(mockClient.getAll).toHaveBeenCalledWith('/users', {
        '$top': '1',
        '$skip': '1',
      });
    });

    it('should throw permission error on 403', async () => {
      mockClient.getAll.mockRejectedValue(new AzureAPIError('Forbidden', '/users', 403));

      await expect(provider.getUsers()).rejects.toThrow(AzurePermissionError);
      await expect(provider.getUsers()).rejects.toThrow('User.Read.All');
    });
  });

  describe('getGroups', () => {
    const mockGroups: AzureGroup[] = [
      {
        id: 'group-1',
        displayName: 'Admins',
        mailEnabled: false,
        securityEnabled: true,
      },
      {
        id: 'group-2',
        displayName: 'Users',
        mailEnabled: true,
        securityEnabled: false,
      },
    ];

    it('should get all groups', async () => {
      mockClient.getAll.mockResolvedValue(mockGroups);

      const groups = await provider.getGroups();

      expect(mockClient.getAll).toHaveBeenCalledWith('/groups', undefined);
      expect(groups).toEqual(mockGroups);
    });

    it('should get groups with filter', async () => {
      mockClient.getAll.mockResolvedValue([mockGroups[0]]);

      const groups = await provider.getGroups({
        filter: 'securityEnabled eq true',
      });

      expect(mockClient.getAll).toHaveBeenCalledWith('/groups', {
        '$filter': 'securityEnabled eq true',
      });
      expect(groups).toHaveLength(1);
    });

    it('should throw permission error on 403', async () => {
      mockClient.getAll.mockRejectedValue(new AzureAPIError('Forbidden', '/groups', 403));

      await expect(provider.getGroups()).rejects.toThrow(AzurePermissionError);
      await expect(provider.getGroups()).rejects.toThrow('Group.Read.All');
    });
  });

  describe('getApplications', () => {
    const mockApps: AzureApp[] = [
      {
        id: 'app-1',
        appId: 'appId-1',
        displayName: 'My App',
      },
    ];

    it('should get all applications', async () => {
      mockClient.getAll.mockResolvedValue(mockApps);

      const apps = await provider.getApplications();

      expect(mockClient.getAll).toHaveBeenCalledWith('/applications', undefined);
      expect(apps).toEqual(mockApps);
    });

    it('should throw permission error on 403', async () => {
      mockClient.getAll.mockRejectedValue(new AzureAPIError('Forbidden', '/applications', 403));

      await expect(provider.getApplications()).rejects.toThrow(AzurePermissionError);
      await expect(provider.getApplications()).rejects.toThrow('Application.Read.All');
    });
  });

  describe('getPolicies', () => {
    const mockPolicies: AzurePolicy[] = [
      {
        id: 'policy-1',
        displayName: 'Require MFA',
        state: 'enabled',
      },
    ];

    it('should get all policies', async () => {
      mockClient.getAll.mockResolvedValue(mockPolicies);

      const policies = await provider.getPolicies();

      expect(mockClient.getAll).toHaveBeenCalledWith(
        '/identity/conditionalAccess/policies',
        undefined
      );
      expect(policies).toEqual(mockPolicies);
    });

    it('should throw permission error on 403', async () => {
      mockClient.getAll.mockRejectedValue(
        new AzureAPIError('Forbidden', '/identity/conditionalAccess/policies', 403)
      );

      await expect(provider.getPolicies()).rejects.toThrow(AzurePermissionError);
      await expect(provider.getPolicies()).rejects.toThrow('Policy.Read.All');
    });
  });

  describe('disconnect', () => {
    it('should disconnect from Graph API', async () => {
      await provider.disconnect();

      expect(mockClient.disconnect).toHaveBeenCalledTimes(1);
    });
  });

  describe('buildQueryParams', () => {
    it('should build complete query params', async () => {
      mockClient.getAll.mockResolvedValue([]);

      await provider.getUsers({
        filter: 'accountEnabled eq true',
        select: ['id', 'displayName'],
        expand: ['memberOf'],
        orderBy: 'displayName',
        top: 10,
        skip: 5,
      });

      expect(mockClient.getAll).toHaveBeenCalledWith('/users', {
        '$filter': 'accountEnabled eq true',
        '$select': 'id,displayName',
        '$expand': 'memberOf',
        '$orderby': 'displayName',
        '$top': '10',
        '$skip': '5',
      });
    });

    it('should return undefined for empty options', async () => {
      mockClient.getAll.mockResolvedValue([]);

      await provider.getUsers({});

      expect(mockClient.getAll).toHaveBeenCalledWith('/users', undefined);
    });
  });
});
