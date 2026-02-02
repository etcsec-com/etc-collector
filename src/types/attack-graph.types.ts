/**
 * Attack Graph Export Types
 *
 * Types for exporting attack path data in a format suitable
 * for visualization tools like BloodHound or custom graph UIs.
 */

/**
 * Node types in the attack graph
 */
export type AttackNodeType = 'user' | 'group' | 'computer' | 'gpo' | 'ou' | 'domain';

/**
 * Risk levels for attack paths
 */
export type AttackPathRisk = 'critical' | 'high' | 'medium' | 'low';

/**
 * Types of attack paths
 */
export type AttackPathType =
  | 'ACL_ABUSE'
  | 'KERBEROASTING'
  | 'ASREP_ROASTING'
  | 'DELEGATION_ABUSE'
  | 'LATERAL_MOVEMENT'
  | 'CERTIFICATE_ABUSE'
  | 'GROUP_MEMBERSHIP'
  | 'DCSYNC'
  | 'OWNERSHIP_ABUSE';

/**
 * Relation types between nodes
 */
export type AttackRelationType =
  | 'MemberOf'
  | 'GenericAll'
  | 'WriteDacl'
  | 'WriteOwner'
  | 'GenericWrite'
  | 'ForceChangePassword'
  | 'AddMember'
  | 'DCSync'
  | 'AllowedToDelegate'
  | 'AllowedToAct'
  | 'HasSPN'
  | 'NoPreauth'
  | 'Owns'
  | 'AdminTo'
  | 'HasSession'
  | 'CanPSRemote'
  | 'CanRDP'
  | 'ExecuteDCOM'
  | 'SQLAdmin'
  | 'ReadLAPSPassword'
  | 'ReadGMSAPassword'
  | 'Contains'
  | 'GPLink'
  | 'TrustedBy';

/**
 * A node in the attack graph
 */
export interface AttackGraphNode {
  id: string; // SID or unique identifier
  name: string; // sAMAccountName or displayName
  type: AttackNodeType;
  sid?: string;
  dn?: string;
  domain?: string;
  isEnabled?: boolean;
  isPrivileged?: boolean;
}

/**
 * A relation in the attack chain
 */
export interface AttackGraphRelation {
  relation: AttackRelationType;
  isAbusable: boolean;
  accessMask?: number;
  objectType?: string;
  description?: string;
}

/**
 * Chain element - either a node or a relation
 */
export type AttackChainElement = AttackGraphNode | AttackGraphRelation;

/**
 * Entry point properties for an attack path
 */
export interface AttackEntryPointProperties {
  hasSPN?: boolean;
  noPreauth?: boolean;
  passwordNotExpire?: boolean;
  unconstrained?: boolean;
  constrained?: boolean;
  rbcd?: boolean;
  adminCount?: boolean;
  enabled?: boolean;
}

/**
 * Entry point for an attack path
 */
export interface AttackEntryPoint {
  id: string;
  name: string;
  type: AttackNodeType;
  properties: AttackEntryPointProperties;
}

/**
 * A complete attack path
 */
export interface AttackPath {
  id: string; // path-001, path-002, etc.
  risk: AttackPathRisk;
  type: AttackPathType;
  hops: number;
  description: string;
  chain: AttackChainElement[];
  entryPoint: AttackEntryPoint;
  target: AttackGraphNode;
  mitigation: string;
}

/**
 * Target information
 */
export interface AttackTarget {
  id: string;
  name: string;
  type: AttackNodeType;
  sid?: string;
  dn?: string;
  reason: string; // Why this is a target (e.g., "Domain Admins", "adminCount=1")
}

/**
 * Statistics for the attack graph
 */
export interface AttackGraphStats {
  totalPaths: number;
  byRisk: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  byType: Record<AttackPathType, number>;
  averageHops: number;
  shortestPath: number;
  longestPath: number;
}

/**
 * Unique node with path count
 */
export interface AttackGraphUniqueNode {
  id: string;
  name: string;
  type: AttackNodeType;
  pathCount: number; // Number of paths this node appears in
  sid?: string;
}

/**
 * Complete attack graph export format
 */
export interface AttackGraphExport {
  version: string;
  generatedAt: string; // ISO 8601 timestamp
  domain: string;
  targets: AttackTarget[];
  paths: AttackPath[];
  stats: AttackGraphStats;
  uniqueNodes: AttackGraphUniqueNode[];
}

/**
 * ACL GUIDs for specific rights
 */
export const ACL_GUIDS = {
  // Extended rights
  FORCE_CHANGE_PASSWORD: '00299570-246d-11d0-a768-00aa006e0529',
  DS_REPLICATION_GET_CHANGES: '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2',
  DS_REPLICATION_GET_CHANGES_ALL: '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2',
  DS_REPLICATION_GET_CHANGES_IN_FILTERED_SET: '89e95b76-444d-4c62-991a-0facbeda640c',

  // Property sets
  SELF_MEMBERSHIP: 'bf9679c0-0de6-11d0-a285-00aa003049e2', // Add self to group

  // Schema objects for LAPS
  LAPS_PASSWORD: 'e91556f8-b3c8-4b66-b3c8-4b0c8ac2c45b',

  // Certificate enrollment
  CERTIFICATE_ENROLLMENT: '0e10c968-78fb-11d2-90d4-00c04f79dc55',
  CERTIFICATE_AUTOENROLLMENT: 'a05b8cc2-17bc-4802-a710-e7c15ab866a2',
} as const;

/**
 * Access mask bits for ACL analysis
 */
export const ACCESS_MASK = {
  GENERIC_READ: 0x80000000,
  GENERIC_WRITE: 0x40000000,
  GENERIC_EXECUTE: 0x20000000,
  GENERIC_ALL: 0x10000000,
  MAXIMUM_ALLOWED: 0x02000000,
  ACCESS_SYSTEM_SECURITY: 0x01000000,
  SYNCHRONIZE: 0x00100000,
  WRITE_OWNER: 0x00080000,
  WRITE_DACL: 0x00040000,
  READ_CONTROL: 0x00020000,
  DELETE: 0x00010000,
  WRITE_PROPERTY: 0x00000020,
  READ_PROPERTY: 0x00000010,
  SELF: 0x00000008,
  LIST_OBJECT: 0x00000080,
  DELETE_TREE: 0x00000040,
  CONTROL_ACCESS: 0x00000100, // Extended right
} as const;

/**
 * Well-known privileged SID suffixes (relative to domain SID)
 */
export const PRIVILEGED_SID_SUFFIXES = {
  DOMAIN_ADMINS: '-512',
  DOMAIN_USERS: '-513',
  DOMAIN_GUESTS: '-514',
  DOMAIN_COMPUTERS: '-515',
  DOMAIN_CONTROLLERS: '-516',
  SCHEMA_ADMINS: '-518',
  ENTERPRISE_ADMINS: '-519',
  GROUP_POLICY_CREATOR_OWNERS: '-520',
  KEY_ADMINS: '-526',
  ENTERPRISE_KEY_ADMINS: '-527',
  ADMINISTRATORS: '-544',
  BACKUP_OPERATORS: '-551',
  ACCOUNT_OPERATORS: '-548',
  SERVER_OPERATORS: '-549',
  PRINT_OPERATORS: '-550',
} as const;

/**
 * Check if a node element in chain
 */
export function isAttackGraphNode(element: AttackChainElement): element is AttackGraphNode {
  return 'type' in element && 'name' in element && !('relation' in element);
}

/**
 * Check if a relation element in chain
 */
export function isAttackGraphRelation(element: AttackChainElement): element is AttackGraphRelation {
  return 'relation' in element;
}
