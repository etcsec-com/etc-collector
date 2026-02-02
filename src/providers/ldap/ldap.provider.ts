import { ILDAPProvider, SearchOptions, ConnectionTestResult } from '../interfaces/ILDAPProvider';
import { ADUser, ADGroup, ADComputer, ADOU } from '../../types/ad.types';
import { LDAPConfig } from '../../types/config.types';
import { LDAPClient, LDAPConnectionOptions } from './ldap-client';
import { LDAPSanitizer } from './ldap-sanitizer';
import { mapToADUser, mapToADGroup, mapToADComputer, mapToADOU, mapToGeneric } from './ad-mappers';
import { logger } from '../../utils/logger';

/**
 * LDAP Provider Implementation
 *
 * Provides Active Directory connectivity via LDAP/LDAPS.
 * Implements all LDAP operations with sanitization and type mapping.
 *
 * Task 3: Implement LDAP Provider (Story 1.5)
 */
export class LDAPProvider implements ILDAPProvider {
  private client: LDAPClient;
  private config: LDAPConfig;

  /**
   * Get base DN for searches
   */
  getBaseDN(): string {
    return this.config.baseDN;
  }

  /**
   * Get LDAP URL (for debugging)
   */
  getUrl(): string {
    return this.config.url;
  }

  constructor(config: LDAPConfig) {
    this.config = config;

    // Create client with connection options
    const connectionOptions: LDAPConnectionOptions = {
      url: config.url,
      bindDN: config.bindDN,
      bindPassword: config.bindPassword,
      timeout: config.timeout,
      caCertPath: config.caCertPath,
      tlsOptions: {
        rejectUnauthorized: config.tlsVerify,
      },
      skipHostnameVerification: config.skipHostnameVerification,
      tlsServername: config.tlsServername,
    };

    this.client = new LDAPClient(connectionOptions);
  }

  /**
   * Connect and bind to LDAP server
   */
  async connect(): Promise<void> {
    logger.info('Connecting to LDAP server...');
    await this.client.connect();
  }

  /**
   * Disconnect from LDAP server
   */
  async disconnect(): Promise<void> {
    logger.info('Disconnecting from LDAP server...');
    await this.client.disconnect();
  }

  /**
   * Test LDAP connection
   */
  async testConnection(): Promise<ConnectionTestResult> {
    logger.info('Testing LDAP connection...');

    const result = await this.client.testConnection();

    if (result.success) {
      // Determine protocol from URL
      const protocol = this.config.url.startsWith('ldaps://') ? 'ldaps' : 'ldap';

      return {
        success: true,
        message: 'Connection successful',
        details: {
          url: this.config.url,
          baseDN: this.config.baseDN,
          protocol,
          bindDN: this.config.bindDN,
          responseTime: result.responseTime,
        },
      };
    } else {
      return {
        success: false,
        message: 'Connection failed',
      };
    }
  }

  /**
   * Search for users in Active Directory
   *
   * Default filter: (&(objectClass=user)(objectCategory=person))
   */
  async searchUsers(filter?: string, attributes?: string[]): Promise<ADUser[]> {
    // Build filter with sanitization
    const userFilter = filter
      ? `(&(objectClass=user)(objectCategory=person)${filter})`
      : '(&(objectClass=user)(objectCategory=person))';

    logger.debug(`Searching for users with filter: ${userFilter}`);

    // Default attributes for users
    const defaultAttributes = [
      'dn',
      'sAMAccountName',
      'userPrincipalName',
      'displayName',
      'userAccountControl',
      'pwdLastSet',
      'lastLogon',
      'adminCount',
      'memberOf',
    ];

    const searchOptions: SearchOptions = {
      filter: userFilter,
      scope: 'sub',
      attributes: attributes || defaultAttributes,
      paged: true,
    };

    const entries = await this.client.search(this.config.baseDN, searchOptions);

    // Map entries to ADUser objects
    return entries.map(mapToADUser);
  }

  /**
   * Search for groups in Active Directory
   *
   * Default filter: (objectClass=group)
   */
  async searchGroups(filter?: string, attributes?: string[]): Promise<ADGroup[]> {
    // Build filter
    const groupFilter = filter ? `(&(objectClass=group)${filter})` : '(objectClass=group)';

    logger.debug(`Searching for groups with filter: ${groupFilter}`);

    // Default attributes for groups
    const defaultAttributes = [
      'dn',
      'sAMAccountName',
      'displayName',
      'groupType',
      'memberOf',
      'member',
    ];

    const searchOptions: SearchOptions = {
      filter: groupFilter,
      scope: 'sub',
      attributes: attributes || defaultAttributes,
      paged: true,
    };

    const entries = await this.client.search(this.config.baseDN, searchOptions);

    // Map entries to ADGroup objects
    return entries.map(mapToADGroup);
  }

  /**
   * Search for computers in Active Directory
   *
   * Default filter: (objectClass=computer)
   */
  async searchComputers(filter?: string, attributes?: string[]): Promise<ADComputer[]> {
    // Build filter
    const computerFilter = filter ? `(&(objectClass=computer)${filter})` : '(objectClass=computer)';

    logger.debug(`Searching for computers with filter: ${computerFilter}`);

    // Default attributes for computers
    const defaultAttributes = [
      'dn',
      'sAMAccountName',
      'dNSHostName',
      'operatingSystem',
      'operatingSystemVersion',
      'lastLogon',
      'userAccountControl',
    ];

    const searchOptions: SearchOptions = {
      filter: computerFilter,
      scope: 'sub',
      attributes: attributes || defaultAttributes,
      paged: true,
    };

    const entries = await this.client.search(this.config.baseDN, searchOptions);

    // Map entries to ADComputer objects
    return entries.map(mapToADComputer);
  }

  /**
   * Search for organizational units in Active Directory
   *
   * Default filter: (objectClass=organizationalUnit)
   */
  async searchOUs(filter?: string, attributes?: string[]): Promise<ADOU[]> {
    // Build filter
    const ouFilter = filter
      ? `(&(objectClass=organizationalUnit)${filter})`
      : '(objectClass=organizationalUnit)';

    logger.debug(`Searching for OUs with filter: ${ouFilter}`);

    // Default attributes for OUs
    const defaultAttributes = ['dn', 'name', 'ou', 'description'];

    const searchOptions: SearchOptions = {
      filter: ouFilter,
      scope: 'sub',
      attributes: attributes || defaultAttributes,
      paged: true,
    };

    const entries = await this.client.search(this.config.baseDN, searchOptions);

    // Map entries to ADOU objects
    return entries.map(mapToADOU);
  }

  /**
   * Generic LDAP search
   *
   * Performs a low-level LDAP search with custom base DN and options.
   */
  async search<T>(baseDN: string, options: SearchOptions): Promise<T[]> {
    logger.debug(`Generic LDAP search: baseDN=${baseDN}, filter=${options.filter}`);

    // Validate filter syntax
    if (!LDAPSanitizer.isValidFilter(options.filter)) {
      throw new Error(`Invalid LDAP filter syntax: ${options.filter}`);
    }

    // Validate base DN
    if (!LDAPSanitizer.isValidDN(baseDN)) {
      throw new Error(`Invalid LDAP DN: ${baseDN}`);
    }

    const entries = await this.client.search(baseDN, options);

    // Map to generic objects
    return entries.map((entry) => mapToGeneric(entry) as T);
  }

  /**
   * Build a safe LDAP filter
   *
   * Utility method to build filters with sanitization.
   *
   * @param attribute - Attribute name
   * @param operator - Comparison operator
   * @param value - Value to filter by (will be sanitized)
   * @returns Safe LDAP filter
   */
  buildSafeFilter(
    attribute: string,
    operator: '=' | '>=' | '<=' | '~=' | '=*',
    value: string
  ): string {
    return LDAPSanitizer.buildFilter(attribute, operator, value);
  }

  /**
   * Build a logical filter (AND/OR/NOT)
   *
   * Utility method to combine multiple filters.
   *
   * @param operator - Logical operator
   * @param filters - Array of filter strings
   * @returns Combined filter
   */
  buildLogicalFilter(operator: '&' | '|' | '!', filters: string[]): string {
    return LDAPSanitizer.buildLogicalFilter(operator, filters);
  }
}
