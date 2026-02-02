import { AzureUser, AzureGroup, AzureApp, AzurePolicy } from '../../types/azure.types';

/**
 * Microsoft Graph Provider Interface
 *
 * Defines the contract for Microsoft Graph API / Azure AD connectivity.
 * Implementations must support OAuth 2.0 client credentials flow with rate limiting.
 *
 * Task 1: Define Azure Provider Interface (Story 1.6)
 */

/**
 * Azure connection test result
 */
export interface AzureConnectionTestResult {
  success: boolean;
  message: string;
  details?: {
    tenantId: string;
    clientId: string;
    graphApiUrl: string;
    authenticated: boolean;
    permissions?: string[];
    responseTime: number; // milliseconds
  };
}

/**
 * Query options for Graph API
 */
export interface GraphQueryOptions {
  filter?: string;
  select?: string[];
  expand?: string[];
  orderBy?: string;
  top?: number;
  skip?: number;
}

/**
 * Microsoft Graph Provider Interface
 *
 * Provides methods for connecting to Microsoft Graph API and querying Azure AD objects.
 */
export interface IGraphProvider {
  /**
   * Authenticate with Microsoft Graph
   *
   * Obtains an access token using OAuth 2.0 client credentials flow.
   * The token is cached and automatically refreshed when expired.
   *
   * @throws {AzureAuthenticationError} If authentication fails
   */
  authenticate(): Promise<void>;

  /**
   * Test connection to Microsoft Graph API
   *
   * Verifies that the client credentials are valid and can authenticate with Graph API.
   * Returns detailed diagnostics including tenant info and permissions.
   *
   * @returns Connection test result with success status and diagnostics
   */
  testConnection(): Promise<AzureConnectionTestResult>;

  /**
   * Query Azure AD users
   *
   * Retrieves users from Azure AD with optional filtering and pagination.
   *
   * @param options - Query options (filter, select, top, etc.)
   * @returns Array of Azure AD users
   * @throws {AzureAPIError} If the API request fails
   */
  getUsers(options?: GraphQueryOptions): Promise<AzureUser[]>;

  /**
   * Query Azure AD groups
   *
   * Retrieves security and Microsoft 365 groups from Azure AD.
   *
   * @param options - Query options (filter, select, top, etc.)
   * @returns Array of Azure AD groups
   * @throws {AzureAPIError} If the API request fails
   */
  getGroups(options?: GraphQueryOptions): Promise<AzureGroup[]>;

  /**
   * Query Azure AD applications
   *
   * Retrieves application registrations from Azure AD.
   *
   * @param options - Query options (filter, select, top, etc.)
   * @returns Array of Azure AD applications
   * @throws {AzureAPIError} If the API request fails
   */
  getApplications(options?: GraphQueryOptions): Promise<AzureApp[]>;

  /**
   * Query Conditional Access policies
   *
   * Retrieves Conditional Access policies from Azure AD.
   *
   * @param options - Query options (filter, select, top, etc.)
   * @returns Array of Conditional Access policies
   * @throws {AzureAPIError} If the API request fails
   */
  getPolicies(options?: GraphQueryOptions): Promise<AzurePolicy[]>;

  /**
   * Disconnect from Microsoft Graph
   *
   * Clears any cached tokens or connection state.
   * Safe to call multiple times.
   */
  disconnect(): Promise<void>;
}
