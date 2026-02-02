import { Client, SearchResult, Entry } from 'ldapts';
import { logger } from '../../utils/logger';
import { SearchOptions, LDAPControl } from '../interfaces/ILDAPProvider';
import { retryWithBackoff, LDAP_RETRY_OPTIONS } from './ldap-retry';
import * as fs from 'fs';
import * as path from 'path';

/**
 * LDAP Client Wrapper
 *
 * Wraps ldapts library to provide LDAP connectivity.
 * Handles connection lifecycle, search operations, and error handling.
 *
 * Task 3: Implement LDAP Provider (Story 1.5)
 */

/**
 * LDAP connection options
 */
export interface LDAPConnectionOptions {
  url: string;
  bindDN: string;
  bindPassword: string;
  timeout?: number;
  tlsOptions?: {
    rejectUnauthorized?: boolean;
    ca?: Buffer | Buffer[];
    checkServerIdentity?: (hostname: string, cert: unknown) => Error | undefined;
    servername?: string;
  };
  caCertPath?: string;
  skipHostnameVerification?: boolean;
  tlsServername?: string;
}

/**
 * LDAP Client
 *
 * Low-level wrapper around ldapts client.
 */
export class LDAPClient {
  private client: Client | null = null;
  private options: LDAPConnectionOptions;
  private isConnected = false;

  constructor(options: LDAPConnectionOptions) {
    this.options = options;
  }

  /**
   * Connect and bind to LDAP server
   *
   * Uses retry logic with exponential backoff for transient failures.
   *
   * @throws Error if connection or bind fails after retries
   */
  async connect(): Promise<void> {
    if (this.isConnected) {
      logger.debug('LDAP client already connected');
      return;
    }

    await retryWithBackoff(async () => {
      try {
        logger.debug(`Connecting to LDAP server: ${this.options.url}`);

        // Build TLS options
        let tlsOptions = this.options.tlsOptions || {};

        // Load CA certificate if path provided and TLS verification is enabled
        // Skip CA cert loading if rejectUnauthorized is explicitly false
        const shouldLoadCaCert =
          this.options.caCertPath && tlsOptions.rejectUnauthorized !== false;

        if (shouldLoadCaCert) {
          try {
            const certPath = path.resolve(this.options.caCertPath!);
            if (fs.existsSync(certPath)) {
              const caCert = fs.readFileSync(certPath);
              tlsOptions = {
                ...tlsOptions,
                ca: caCert,
              };
              logger.debug(`Loaded CA certificate from: ${certPath}`);
            } else {
              logger.warn(`CA certificate not found at ${certPath}, using system CA store`);
            }
          } catch (error) {
            logger.warn(`Failed to load CA certificate from ${this.options.caCertPath}:`, error);
            // Don't throw - fall back to system CA store
          }
        } else if (tlsOptions.rejectUnauthorized === false) {
          logger.debug('TLS verification disabled (rejectUnauthorized=false)');
        }

        // Use servername for TLS validation when connecting via IP but cert has hostname
        if (this.options.tlsServername) {
          tlsOptions = {
            ...tlsOptions,
            servername: this.options.tlsServername,
          };
          logger.debug(`Using TLS servername for certificate validation: ${this.options.tlsServername}`);
        }

        // Skip hostname verification if configured (for IP-based connections)
        if (this.options.skipHostnameVerification) {
          tlsOptions = {
            ...tlsOptions,
            checkServerIdentity: (hostname: string, _cert: unknown): undefined => {
              logger.debug(`Skipping hostname verification for: ${hostname}`);
              return undefined;
            },
          };
          logger.debug('Hostname verification disabled (skipHostnameVerification=true)');
        }

        // Create client
        this.client = new Client({
          url: this.options.url,
          timeout: this.options.timeout || 5000,
          connectTimeout: this.options.timeout || 5000,
          tlsOptions,
        });

        // Bind to server
        await this.client.bind(this.options.bindDN, this.options.bindPassword);

        this.isConnected = true;
        logger.info(`Connected to LDAP server: ${this.options.url}`);
      } catch (error) {
        this.isConnected = false;
        this.client = null;
        logger.error('Failed to connect to LDAP server:', error);
        throw new Error(
          `LDAP connection failed: ${error instanceof Error ? error.message : 'Unknown error'}`
        );
      }
    }, LDAP_RETRY_OPTIONS);
  }

  /**
   * Disconnect from LDAP server
   */
  async disconnect(): Promise<void> {
    if (!this.client) {
      return;
    }

    try {
      await this.client.unbind();
      logger.debug('Disconnected from LDAP server');
    } catch (error) {
      logger.warn('Error during LDAP disconnect:', error);
    } finally {
      this.client = null;
      this.isConnected = false;
    }
  }

  /**
   * Test connection to LDAP server
   *
   * @returns Connection test with response time
   */
  async testConnection(): Promise<{ success: boolean; responseTime: number }> {
    const startTime = Date.now();

    try {
      // Attempt to connect and bind
      await this.connect();

      const responseTime = Date.now() - startTime;

      return {
        success: true,
        responseTime,
      };
    } catch (error) {
      logger.error('LDAP connection test failed:', error);
      return {
        success: false,
        responseTime: Date.now() - startTime,
      };
    }
  }

  /**
   * Search LDAP directory
   *
   * Uses retry logic with exponential backoff for transient failures.
   *
   * @param baseDN - Base distinguished name for search
   * @param options - Search options (filter, scope, attributes, etc.)
   * @returns Array of search entry results
   *
   * @throws Error if not connected or search fails after retries
   */
  async search(baseDN: string, options: SearchOptions): Promise<Entry[]> {
    if (!this.client || !this.isConnected) {
      throw new Error('LDAP client not connected. Call connect() first.');
    }

    return retryWithBackoff(async () => {
      try {
        logger.debug(`LDAP search: baseDN=${baseDN}, filter=${options.filter}`);

        // Map our SearchOptions to ldapts SearchOptions
        const searchOptions: any = {
          filter: options.filter,
          scope: options.scope,
          attributes: options.attributes,
          sizeLimit: options.sizeLimit,
          timeLimit: options.timeLimit,
          paged: options.paged ? { pageSize: 1000 } : undefined,
        };

        // Map controls if provided
        if (options.controls && options.controls.length > 0) {
          searchOptions.controls = options.controls.map((ctrl: LDAPControl) => {
            const control: any = {
              type: ctrl.oid,
              critical: ctrl.critical || false,
            };
            if (ctrl.value) {
              control.value = Buffer.isBuffer(ctrl.value) ? ctrl.value : Buffer.from(ctrl.value);
            }
            return control;
          });
        }

        // Perform search
        const searchResult: SearchResult = await this.client!.search(baseDN, searchOptions);

        logger.debug(`LDAP search returned ${searchResult.searchEntries.length} entries`);

        return searchResult.searchEntries;
      } catch (error) {
        logger.error(`LDAP search failed: baseDN=${baseDN}`, error);
        throw new Error(
          `LDAP search failed: ${error instanceof Error ? error.message : 'Unknown error'}`
        );
      }
    }, LDAP_RETRY_OPTIONS);
  }

  /**
   * Check if client is currently connected
   */
  isClientConnected(): boolean {
    return this.isConnected;
  }

  /**
   * Get connection URL (for debugging)
   */
  getConnectionUrl(): string {
    return this.options.url;
  }
}
