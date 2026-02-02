/**
 * Microsoft Graph Provider
 *
 * High-level provider for querying Azure AD / Microsoft Graph API.
 * Implements the IGraphProvider interface with full support for users, groups, applications, and policies.
 *
 * Task 3: Create Azure Provider query methods (Story 1.6)
 */

import {
  IGraphProvider,
  AzureConnectionTestResult,
  GraphQueryOptions,
} from '../interfaces/IGraphProvider';
import { AzureUser, AzureGroup, AzureApp, AzurePolicy } from '../../types/azure.types';
import { AzureProviderConfig } from '../../types/config.types';
import { GraphClient } from './graph-client';
import {
  AzureAPIError,
  AzureAuthenticationError,
  AzurePermissionError,
} from './azure-errors';

/**
 * Microsoft Graph Provider
 *
 * Provides high-level methods for querying Azure AD objects via Microsoft Graph API.
 */
export class GraphProvider implements IGraphProvider {
  private readonly client: GraphClient;
  private readonly config: AzureProviderConfig;
  private readonly graphApiUrl = 'https://graph.microsoft.com';

  constructor(config: AzureProviderConfig) {
    this.config = config;
    this.client = new GraphClient(config, {
      timeout: 30000, // 30 seconds
      maxRetries: 3,
      apiVersion: 'v1.0',
    });
  }

  /**
   * Authenticate with Microsoft Graph
   *
   * @throws {AzureAuthenticationError} If authentication fails
   */
  async authenticate(): Promise<void> {
    await this.client.authenticate();
  }

  /**
   * Test connection to Microsoft Graph API
   *
   * @returns Connection test result with diagnostics
   */
  async testConnection(): Promise<AzureConnectionTestResult> {
    const startTime = Date.now();

    try {
      // Authenticate
      await this.authenticate();

      // Test basic API access by getting organization info
      await this.client.get<{ value: { id: string }[] }>('/organization');

      const responseTime = Date.now() - startTime;

      return {
        success: true,
        message: 'Connection successful',
        details: {
          tenantId: this.config.tenantId,
          clientId: this.config.clientId,
          graphApiUrl: this.graphApiUrl,
          authenticated: true,
          permissions: ['User.Read.All', 'Group.Read.All'], // TODO: Get actual permissions
          responseTime,
        },
      };
    } catch (error) {
      const responseTime = Date.now() - startTime;

      if (error instanceof AzureAuthenticationError) {
        return {
          success: false,
          message: `Authentication failed: ${error.message}`,
          details: {
            tenantId: this.config.tenantId,
            clientId: this.config.clientId,
            graphApiUrl: this.graphApiUrl,
            authenticated: false,
            responseTime,
          },
        };
      }

      return {
        success: false,
        message: `Connection test failed: ${error instanceof Error ? error.message : String(error)}`,
        details: {
          tenantId: this.config.tenantId,
          clientId: this.config.clientId,
          graphApiUrl: this.graphApiUrl,
          authenticated: false,
          responseTime,
        },
      };
    }
  }

  /**
   * Query Azure AD users
   *
   * @param options - Query options (filter, select, top, etc.)
   * @returns Array of Azure AD users
   * @throws {AzureAPIError} If the API request fails
   */
  async getUsers(options?: GraphQueryOptions): Promise<AzureUser[]> {
    try {
      const params = this.buildQueryParams(options);

      // Use getAll to handle pagination
      const users = await this.client.getAll<AzureUser>('/users', params);

      return users;
    } catch (error) {
      if (
        error instanceof AzureAPIError &&
        error.statusCode === 403
      ) {
        throw new AzurePermissionError(
          'Insufficient permissions to read users. Required: User.Read.All',
          '/users',
          ['User.Read.All']
        );
      }
      throw error;
    }
  }

  /**
   * Query Azure AD groups
   *
   * @param options - Query options (filter, select, top, etc.)
   * @returns Array of Azure AD groups
   * @throws {AzureAPIError} If the API request fails
   */
  async getGroups(options?: GraphQueryOptions): Promise<AzureGroup[]> {
    try {
      const params = this.buildQueryParams(options);

      const groups = await this.client.getAll<AzureGroup>('/groups', params);

      return groups;
    } catch (error) {
      if (error instanceof AzureAPIError && error.statusCode === 403) {
        throw new AzurePermissionError(
          'Insufficient permissions to read groups. Required: Group.Read.All',
          '/groups',
          ['Group.Read.All']
        );
      }
      throw error;
    }
  }

  /**
   * Query Azure AD applications
   *
   * @param options - Query options (filter, select, top, etc.)
   * @returns Array of Azure AD applications
   * @throws {AzureAPIError} If the API request fails
   */
  async getApplications(options?: GraphQueryOptions): Promise<AzureApp[]> {
    try {
      const params = this.buildQueryParams(options);

      const apps = await this.client.getAll<AzureApp>('/applications', params);

      return apps;
    } catch (error) {
      if (error instanceof AzureAPIError && error.statusCode === 403) {
        throw new AzurePermissionError(
          'Insufficient permissions to read applications. Required: Application.Read.All',
          '/applications',
          ['Application.Read.All']
        );
      }
      throw error;
    }
  }

  /**
   * Query Conditional Access policies
   *
   * @param options - Query options (filter, select, top, etc.)
   * @returns Array of Conditional Access policies
   * @throws {AzureAPIError} If the API request fails
   */
  async getPolicies(options?: GraphQueryOptions): Promise<AzurePolicy[]> {
    try {
      const params = this.buildQueryParams(options);

      const policies = await this.client.getAll<AzurePolicy>(
        '/identity/conditionalAccess/policies',
        params
      );

      return policies;
    } catch (error) {
      if (error instanceof AzureAPIError && error.statusCode === 403) {
        throw new AzurePermissionError(
          'Insufficient permissions to read policies. Required: Policy.Read.All',
          '/identity/conditionalAccess/policies',
          ['Policy.Read.All']
        );
      }
      throw error;
    }
  }

  /**
   * Get organization/tenant information
   *
   * @returns Organization info with display name
   */
  async getOrganization(): Promise<{ displayName: string; id: string; verifiedDomains: string[] }> {
    await this.authenticate();
    const response = await this.client.get<{
      value: Array<{
        id: string;
        displayName: string;
        verifiedDomains: Array<{ name: string; isDefault: boolean }>;
      }>;
    }>('/organization');

    const org = response.value[0];
    return {
      id: org?.id || this.config.tenantId,
      displayName: org?.displayName || 'Unknown',
      verifiedDomains: org?.verifiedDomains?.map((d) => d.name) || [],
    };
  }

  /**
   * Disconnect from Microsoft Graph
   *
   * Clears cached tokens and connection state.
   */
  async disconnect(): Promise<void> {
    this.client.disconnect();
  }

  /**
   * Build OData query parameters from options
   *
   * @param options - Query options
   * @returns Query parameters for Graph API
   */
  private buildQueryParams(options?: GraphQueryOptions): Record<string, string> | undefined {
    if (!options) {
      return undefined;
    }

    const params: Record<string, string> = {};

    if (options.filter) {
      params['$filter'] = options.filter;
    }

    if (options.select && options.select.length > 0) {
      params['$select'] = options.select.join(',');
    }

    if (options.expand && options.expand.length > 0) {
      params['$expand'] = options.expand.join(',');
    }

    if (options.orderBy) {
      params['$orderby'] = options.orderBy;
    }

    if (options.top !== undefined) {
      params['$top'] = String(options.top);
    }

    if (options.skip !== undefined) {
      params['$skip'] = String(options.skip);
    }

    return Object.keys(params).length > 0 ? params : undefined;
  }
}
