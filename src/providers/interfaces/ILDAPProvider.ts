import { ADUser, ADGroup, ADComputer, ADOU } from '../../types/ad.types';

/**
 * LDAP Provider Interface
 *
 * Defines the contract for LDAP/Active Directory connectivity.
 * Implementations must support LDAP (389) and LDAPS (636) with TLS verification.
 *
 * Task 1: Define LDAP Provider Interface (Story 1.5)
 */

/**
 * LDAP Control
 */
export interface LDAPControl {
  oid: string;
  critical?: boolean;
  value?: Buffer | string;
}

/**
 * LDAP search options
 */
export interface SearchOptions {
  filter: string;
  scope: 'base' | 'one' | 'sub';
  attributes?: string[];
  sizeLimit?: number;
  timeLimit?: number;
  paged?: boolean;
  controls?: LDAPControl[];
}

/**
 * Connection test result
 */
export interface ConnectionTestResult {
  success: boolean;
  message: string;
  details?: {
    url: string;
    baseDN: string;
    protocol: 'ldap' | 'ldaps';
    bindDN: string;
    responseTime: number; // milliseconds
  };
}

/**
 * LDAP Provider Interface
 *
 * Provides methods for connecting to Active Directory and querying objects.
 */
export interface ILDAPProvider {
  /**
   * Connect and bind to LDAP server
   *
   * Establishes connection and authenticates with bind DN/password.
   * Supports both LDAP (389) and LDAPS (636) protocols.
   *
   * @throws Error if connection or bind fails
   */
  connect(): Promise<void>;

  /**
   * Disconnect from LDAP server
   *
   * Cleanly closes the LDAP connection.
   * Safe to call even if not connected.
   */
  disconnect(): Promise<void>;

  /**
   * Test LDAP connection
   *
   * Verifies connectivity to LDAP server and performs a test bind.
   * Returns detailed connection information including response time.
   *
   * @returns Connection test result with success status and details
   */
  testConnection(): Promise<ConnectionTestResult>;

  /**
   * Search for users in Active Directory
   *
   * Queries for user objects matching the filter.
   * Default filter: (objectClass=user)(objectCategory=person)
   *
   * @param filter - Optional LDAP filter (default: all users)
   * @param attributes - Optional attributes to retrieve (default: all)
   * @returns Array of AD user objects
   */
  searchUsers(filter?: string, attributes?: string[]): Promise<ADUser[]>;

  /**
   * Search for groups in Active Directory
   *
   * Queries for group objects matching the filter.
   * Default filter: (objectClass=group)
   *
   * @param filter - Optional LDAP filter (default: all groups)
   * @param attributes - Optional attributes to retrieve (default: all)
   * @returns Array of AD group objects
   */
  searchGroups(filter?: string, attributes?: string[]): Promise<ADGroup[]>;

  /**
   * Search for computers in Active Directory
   *
   * Queries for computer objects matching the filter.
   * Default filter: (objectClass=computer)
   *
   * @param filter - Optional LDAP filter (default: all computers)
   * @param attributes - Optional attributes to retrieve (default: all)
   * @returns Array of AD computer objects
   */
  searchComputers(filter?: string, attributes?: string[]): Promise<ADComputer[]>;

  /**
   * Search for organizational units in Active Directory
   *
   * Queries for OU objects matching the filter.
   * Default filter: (objectClass=organizationalUnit)
   *
   * @param filter - Optional LDAP filter (default: all OUs)
   * @param attributes - Optional attributes to retrieve (default: all)
   * @returns Array of AD OU objects
   */
  searchOUs(filter?: string, attributes?: string[]): Promise<ADOU[]>;

  /**
   * Generic LDAP search
   *
   * Performs a low-level LDAP search with custom base DN and options.
   * Use this for advanced queries or custom object types.
   *
   * @param baseDN - Base distinguished name for search
   * @param options - Search options (filter, scope, attributes, etc.)
   * @returns Array of search results
   */
  search<T>(baseDN: string, options: SearchOptions): Promise<T[]>;
}
