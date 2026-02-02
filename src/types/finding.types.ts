/**
 * Vulnerability Finding Types
 *
 * Type definitions for security vulnerability findings.
 * Story 1.7: AD Vulnerability Detection Engine
 */

/**
 * Enriched user entity for affectedEntities
 * Contains AD attributes for detailed reporting
 */
export interface AffectedUserEntity {
  // Type discriminator
  type: 'user';

  // Identity (5)
  dn: string;
  sAMAccountName: string;
  userPrincipalName: string | null;
  displayName: string | null;
  mail: string | null;

  // Organization (8)
  title: string | null;
  department: string | null;
  company: string | null;
  manager: string | null;
  physicalDeliveryOfficeName: string | null;
  description: string | null;
  employeeID: string | null;
  telephoneNumber: string | null;

  // Dates (5)
  whenCreated: string | null;
  whenChanged: string | null;
  lastLogon: string | null;
  pwdLastSet: string | null;
  accountExpires: string | null;

  // Security (4)
  badPwdCount: number;
  lockoutTime: string | null;
  adminCount: number;
  memberOf: string[];
  enabled: boolean;
}

/**
 * Enriched Azure user entity for affectedEntities
 * Contains Azure AD/Entra ID attributes for detailed reporting
 */
export interface AffectedAzureUserEntity {
  // Type discriminator
  type: 'azureUser';

  // Identity (5)
  id: string;
  userPrincipalName: string;
  displayName: string | null;
  mail: string | null;
  givenName: string | null;
  surname: string | null;

  // Organization (6)
  jobTitle: string | null;
  department: string | null;
  companyName: string | null;
  manager: string | null;
  officeLocation: string | null;
  employeeId: string | null;

  // Dates (3)
  createdDateTime: string | null;
  lastSignInDateTime: string | null;
  lastPasswordChangeDateTime: string | null;

  // Security (7)
  accountEnabled: boolean;
  userType: string | null; // "Member" | "Guest"
  riskLevel: string | null; // "none" | "low" | "medium" | "high" | "hidden"
  riskState: string | null; // "none" | "confirmedSafe" | "remediated" | "dismissed" | "atRisk" | "confirmedCompromised"
  isMfaRegistered: boolean;
  assignedLicenses: string[];
  memberOf: string[]; // Group/role IDs or names
}

/**
 * Enriched application entity for affectedEntities
 * Used for Azure AD applications and service principals
 */
export interface AffectedAppEntity {
  id: string; // appId or objectId
  displayName: string;
  type: 'application' | 'servicePrincipal';

  // App details
  appId: string | null;
  signInAudience: string | null; // "AzureADMyOrg" | "AzureADMultipleOrgs" | etc.
  createdDateTime: string | null;

  // Security
  publisherDomain: string | null;
  verifiedPublisher: boolean;
  credentialCount: number;
  oldestCredentialExpiry: string | null;
}

/**
 * Enriched group entity for affectedEntities
 * Used for both AD and Azure groups
 */
export interface AffectedGroupEntity {
  id: string; // DN for AD, objectId for Azure
  displayName: string;
  type: 'group';

  // AD-specific
  sAMAccountName: string | null;
  groupType: string | null; // "Security" | "Distribution"
  groupScope: string | null; // "DomainLocal" | "Global" | "Universal"

  // Azure-specific
  securityEnabled: boolean | null;
  mailEnabled: boolean | null;
  groupTypes: string[]; // ["Unified", "DynamicMembership"]

  // Common
  memberCount: number | null;
  description: string | null;
}

/**
 * Enriched computer entity for affectedEntities
 * Used for AD computer objects
 */
export interface AffectedComputerEntity {
  id: string; // DN
  displayName: string;
  type: 'computer';

  // Identity
  sAMAccountName: string;
  dNSHostName: string | null;

  // OS Info
  operatingSystem: string | null;
  operatingSystemVersion: string | null;

  // Dates
  whenCreated: string | null;
  whenChanged: string | null;
  lastLogon: string | null;
  pwdLastSet: string | null;

  // Security
  enabled: boolean;
  userAccountControl: number;
}

/**
 * Vulnerability severity levels
 */
export type Severity = 'critical' | 'high' | 'medium' | 'low';

/**
 * Vulnerability category
 */
export type Category =
  | 'passwords'
  | 'kerberos'
  | 'accounts'
  | 'groups'
  | 'computers'
  | 'advanced'
  | 'permissions'
  | 'config'
  | 'adcs' // AD Certificate Services (ESC1-ESC11)
  | 'gpo' // Group Policy security
  | 'trusts' // Domain trust relationships
  | 'attack-paths' // Privilege escalation paths (Phase 2)
  | 'monitoring' // Security monitoring gaps (Phase 2)
  | 'compliance' // Security framework compliance (Phase 3)
  | 'network' // Network infrastructure security (Phase 3)
  | 'identity' // Azure AD identity vulnerabilities
  | 'applications' // Azure AD applications
  | 'conditionalAccess' // Azure Conditional Access
  | 'privilegedAccess'; // Azure privileged access

/**
 * Single vulnerability finding
 */
export interface Finding {
  /**
   * Vulnerability type identifier (e.g., "PASSWORD_NOT_REQUIRED")
   */
  type: string;

  /**
   * Severity level
   */
  severity: Severity;

  /**
   * Category classification
   */
  category: Category;

  /**
   * Human-readable title
   */
  title: string;

  /**
   * Detailed description
   */
  description: string;

  /**
   * Number of affected entities (unique objects)
   * Used for scoring and actionable remediation
   */
  count: number;

  /**
   * Total instances found (e.g., total ACE entries for permissions)
   * Optional - only present when count differs from total instances
   * Used for forensics and detailed audit trail
   */
  totalInstances?: number;

  /**
   * List of affected entities (optional, if includeDetails=true)
   * Can be enriched entity objects with type discriminator for uniform aggregation
   */
  affectedEntities?: (
    | string
    | AffectedUserEntity
    | AffectedAzureUserEntity
    | AffectedAppEntity
    | AffectedGroupEntity
    | AffectedComputerEntity
  )[];

  /**
   * Additional context-specific details
   */
  details?: Record<string, unknown>;
}

/**
 * Finding counts by severity
 */
export interface FindingCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
  total: number;
}

/**
 * Finding counts by category
 */
export interface CategoryCounts {
  passwords: number;
  kerberos: number;
  accounts: number;
  groups: number;
  computers: number;
  advanced: number;
  permissions: number;
  config: number;
  adcs: number;
  gpo: number;
  trusts: number;
  'attack-paths': number;
  monitoring: number;
  compliance: number;
  network: number;
  identity: number;
  applications: number;
  conditionalAccess: number;
  privilegedAccess: number;
}
