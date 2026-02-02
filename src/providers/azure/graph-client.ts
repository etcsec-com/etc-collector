/**
 * Microsoft Graph Client
 *
 * Handles authentication and API requests to Microsoft Graph using OAuth 2.0 client credentials flow.
 * Supports automatic token refresh and retry logic with rate limit handling.
 *
 * Task 2: Implement Microsoft Graph Client with OAuth 2.0 (Story 1.6)
 */

import { Client } from '@microsoft/microsoft-graph-client';
import { ClientSecretCredential } from '@azure/identity';
import { AzureProviderConfig } from '../../types/config.types';
import {
  AzureAuthenticationError,
  AzureAPIError,
  AzureRateLimitError,
  AzureTimeoutError,
} from './azure-errors';
import { retryWithBackoff, AZURE_RETRY_CONFIGS, RetryOptions } from './azure-retry';

/**
 * Graph client options
 */
export interface GraphClientOptions {
  timeout?: number; // milliseconds (default: 30000)
  maxRetries?: number; // default: 3
  apiVersion?: string; // default: 'v1.0'
}

/**
 * Token info
 */
interface TokenInfo {
  accessToken: string;
  expiresAt: Date;
}

/**
 * Microsoft Graph Client
 *
 * Provides authenticated access to Microsoft Graph API using Azure AD service principal.
 */
export class GraphClient {
  private client: Client | null = null;
  private credential: ClientSecretCredential;
  private tokenInfo: TokenInfo | null = null;
  private readonly config: AzureProviderConfig;
  private readonly options: Required<GraphClientOptions>;
  private readonly graphScope = 'https://graph.microsoft.com/.default';

  constructor(config: AzureProviderConfig, options: GraphClientOptions = {}) {
    this.config = config;
    this.options = {
      timeout: options.timeout || 30000,
      maxRetries: options.maxRetries || 3,
      apiVersion: options.apiVersion || 'v1.0',
    };

    // Initialize Azure AD credential
    this.credential = new ClientSecretCredential(
      config.tenantId,
      config.clientId,
      config.clientSecret
    );
  }

  /**
   * Authenticate and initialize Graph client
   *
   * Obtains an access token using OAuth 2.0 client credentials flow.
   *
   * @throws {AzureAuthenticationError} If authentication fails
   */
  async authenticate(): Promise<void> {
    try {
      // Get access token
      const tokenResponse = await this.credential.getToken(this.graphScope);

      if (!tokenResponse) {
        throw new AzureAuthenticationError(
          'Failed to obtain access token',
          this.config.tenantId,
          this.config.clientId
        );
      }

      // Store token info
      this.tokenInfo = {
        accessToken: tokenResponse.token,
        expiresAt: tokenResponse.expiresOnTimestamp
          ? new Date(tokenResponse.expiresOnTimestamp)
          : new Date(Date.now() + 3600 * 1000), // 1 hour default
      };

      // Initialize Graph client with token
      this.client = Client.init({
        authProvider: (done) => {
          done(null, this.tokenInfo!.accessToken);
        },
        defaultVersion: this.options.apiVersion,
      });
    } catch (error) {
      throw new AzureAuthenticationError(
        `Authentication failed: ${error instanceof Error ? error.message : String(error)}`,
        this.config.tenantId,
        this.config.clientId,
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Check if token is expired or about to expire
   *
   * @returns True if token needs refresh (expired or expires in <5 minutes)
   */
  private isTokenExpired(): boolean {
    if (!this.tokenInfo) {
      return true;
    }

    const now = Date.now();
    const expiresAt = this.tokenInfo.expiresAt.getTime();
    const fiveMinutes = 5 * 60 * 1000;

    return expiresAt - now < fiveMinutes;
  }

  /**
   * Ensure client is authenticated
   *
   * Automatically refreshes token if expired.
   *
   * @throws {AzureAuthenticationError} If not authenticated and authentication fails
   */
  private async ensureAuthenticated(): Promise<void> {
    if (!this.client || this.isTokenExpired()) {
      await this.authenticate();
    }
  }

  /**
   * Make a GET request to Graph API
   *
   * Handles authentication, rate limiting, and retries automatically.
   *
   * @param endpoint - Graph API endpoint (e.g., '/users', '/groups')
   * @param params - Query parameters
   * @param retryOptions - Override default retry options
   * @returns Response data
   * @throws {AzureAPIError} If request fails
   */
  async get<T = unknown>(
    endpoint: string,
    params?: Record<string, unknown>,
    retryOptions?: RetryOptions
  ): Promise<T> {
    // Wrap the request with retry logic
    return retryWithBackoff(async () => {
      await this.ensureAuthenticated();

      if (!this.client) {
        throw new AzureAPIError('Graph client not initialized', endpoint);
      }

      try {
        let request = this.client.api(endpoint);

        // Add query parameters
        if (params) {
          const queryParams: Record<string, string> = {};
          for (const [key, value] of Object.entries(params)) {
            if (value !== undefined && value !== null) {
              queryParams[key] = String(value);
            }
          }
          if (Object.keys(queryParams).length > 0) {
            request = request.query(queryParams);
          }
        }

        // Set timeout
        request = request.options({
          timeout: this.options.timeout,
        });

        // Execute request
        const response = await request.get();
        return response as T;
      } catch (error) {
        // Handle rate limit (429)
        if (error instanceof Error && 'statusCode' in error && error.statusCode === 429) {
          const retryAfter = this.extractRetryAfter(error);
          throw new AzureRateLimitError(
            `Rate limit exceeded for ${endpoint}. Retry after ${retryAfter}s`,
            endpoint,
            retryAfter
          );
        }

        // Handle timeout
        if (error instanceof Error && error.message.includes('timeout')) {
          throw new AzureTimeoutError(
            `Request to ${endpoint} timed out after ${this.options.timeout}ms`,
            `GET ${endpoint}`,
            this.options.timeout
          );
        }

        // Generic API error
        const statusCode =
          error instanceof Error && 'statusCode' in error
            ? (error as { statusCode: number }).statusCode
            : undefined;

        throw new AzureAPIError(
          `Graph API request failed: ${error instanceof Error ? error.message : String(error)}`,
          endpoint,
          statusCode,
          error instanceof Error ? error : undefined
        );
      }
    }, retryOptions || AZURE_RETRY_CONFIGS.default);
  }

  /**
   * Get all results with pagination
   *
   * Automatically follows @odata.nextLink to retrieve all pages.
   *
   * @param endpoint - Graph API endpoint
   * @param params - Query parameters
   * @returns Array of all results
   */
  async getAll<T = unknown>(endpoint: string, params?: Record<string, unknown>): Promise<T[]> {
    const results: T[] = [];
    let nextLink: string | undefined = endpoint;
    let currentParams: Record<string, unknown> | undefined = params;

    while (nextLink) {
      const response: { value: T[]; '@odata.nextLink'?: string } = await this.get<{
        value: T[];
        '@odata.nextLink'?: string;
      }>(nextLink, currentParams);

      if (response.value && Array.isArray(response.value)) {
        results.push(...response.value);
      }

      nextLink = response['@odata.nextLink'];
      // For subsequent pages, don't pass params (they're in the nextLink)
      currentParams = undefined;
    }

    return results;
  }

  /**
   * Extract retry-after value from error
   *
   * @param error - Error object
   * @returns Retry after seconds (default: 60)
   */
  private extractRetryAfter(error: Error): number {
    try {
      if ('headers' in error && error.headers && typeof error.headers === 'object') {
        const headers = error.headers as Record<string, string>;
        const retryAfter = headers['retry-after'] || headers['Retry-After'];
        if (retryAfter) {
          const seconds = parseInt(retryAfter, 10);
          if (!isNaN(seconds)) {
            return seconds;
          }
        }
      }
    } catch {
      // Ignore parsing errors
    }
    return 60; // Default to 60 seconds
  }

  /**
   * Test connection to Microsoft Graph
   *
   * Verifies authentication and basic API access.
   *
   * @returns True if connection is successful
   * @throws {AzureAuthenticationError | AzureAPIError} If connection fails
   */
  async testConnection(): Promise<boolean> {
    await this.authenticate();

    // Try a simple API call to verify access
    await this.get('/organization');

    return true;
  }

  /**
   * Get current access token
   *
   * @returns Access token or null if not authenticated
   */
  getAccessToken(): string | null {
    return this.tokenInfo?.accessToken || null;
  }

  /**
   * Clear cached token and client
   */
  disconnect(): void {
    this.client = null;
    this.tokenInfo = null;
  }
}
