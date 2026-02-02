/**
 * Domain Trust Types
 *
 * Enhanced types for trust relationship security analysis.
 */

/**
 * Extended Trust Relationship with security analysis fields
 */
export interface ADTrustExtended {
  name: string;
  dn: string;

  // Direction
  trustDirection: number; // 1=inbound, 2=outbound, 3=bidirectional
  direction: 'inbound' | 'outbound' | 'bidirectional';

  // Type
  trustType: number;
  type: 'forest' | 'external' | 'realm' | 'shortcut' | 'parent-child';

  // Attributes for security analysis
  trustAttributes: number;

  // Computed security flags
  sidFilteringEnabled: boolean;
  selectiveAuthEnabled: boolean;
  isTransitive: boolean;

  // Partner domain info
  flatName?: string;
  trustPartner?: string;

  // Encryption types (msDS-SupportedEncryptionTypes)
  // Bit flags: 0x1=DES-CBC-CRC, 0x2=DES-CBC-MD5, 0x4=RC4-HMAC, 0x8=AES128, 0x10=AES256
  supportedEncryptionTypes?: number;

  // Dates for activity detection
  whenCreated?: Date;
  whenChanged?: Date;
}

// Trust Direction values
export const TRUST_DIRECTION_INBOUND = 1;
export const TRUST_DIRECTION_OUTBOUND = 2;
export const TRUST_DIRECTION_BIDIRECTIONAL = 3;

// Trust Type values
export const TRUST_TYPE_DOWNLEVEL = 1; // Windows NT domain
export const TRUST_TYPE_UPLEVEL = 2; // Active Directory domain
export const TRUST_TYPE_MIT = 3; // Kerberos realm (non-Windows)
export const TRUST_TYPE_DCE = 4; // DCE realm

// Trust Attribute bit flags
export const TRUST_ATTRIBUTE_NON_TRANSITIVE = 0x00000001;
export const TRUST_ATTRIBUTE_UPLEVEL_ONLY = 0x00000002;
export const TRUST_ATTRIBUTE_QUARANTINED_DOMAIN = 0x00000004; // SID filtering enabled
export const TRUST_ATTRIBUTE_FOREST_TRANSITIVE = 0x00000008;
export const TRUST_ATTRIBUTE_CROSS_ORGANIZATION = 0x00000010; // Selective authentication
export const TRUST_ATTRIBUTE_WITHIN_FOREST = 0x00000020;
export const TRUST_ATTRIBUTE_TREAT_AS_EXTERNAL = 0x00000040;
export const TRUST_ATTRIBUTE_USES_RC4_ENCRYPTION = 0x00000080;
export const TRUST_ATTRIBUTE_CROSS_ORGANIZATION_NO_TGT_DELEGATION = 0x00000200;
export const TRUST_ATTRIBUTE_PIM_TRUST = 0x00000400;

/**
 * Helper function to parse trust direction
 */
export function parseTrustDirection(direction: number): 'inbound' | 'outbound' | 'bidirectional' {
  switch (direction) {
    case TRUST_DIRECTION_INBOUND:
      return 'inbound';
    case TRUST_DIRECTION_OUTBOUND:
      return 'outbound';
    case TRUST_DIRECTION_BIDIRECTIONAL:
      return 'bidirectional';
    default:
      return 'inbound';
  }
}

/**
 * Helper function to parse trust type
 */
export function parseTrustType(type: number, attributes: number): 'forest' | 'external' | 'realm' | 'shortcut' | 'parent-child' {
  // Check if it's a forest trust
  if ((attributes & TRUST_ATTRIBUTE_FOREST_TRANSITIVE) !== 0) {
    return 'forest';
  }

  // Check if within forest (parent-child)
  if ((attributes & TRUST_ATTRIBUTE_WITHIN_FOREST) !== 0) {
    return 'parent-child';
  }

  switch (type) {
    case TRUST_TYPE_MIT:
      return 'realm';
    case TRUST_TYPE_UPLEVEL:
    case TRUST_TYPE_DOWNLEVEL:
    default:
      return 'external';
  }
}

/**
 * Check if SID filtering is enabled
 */
export function isSidFilteringEnabled(attributes: number): boolean {
  return (attributes & TRUST_ATTRIBUTE_QUARANTINED_DOMAIN) !== 0;
}

/**
 * Check if selective authentication is enabled
 */
export function isSelectiveAuthEnabled(attributes: number): boolean {
  return (attributes & TRUST_ATTRIBUTE_CROSS_ORGANIZATION) !== 0;
}

/**
 * Check if trust is transitive
 */
export function isTrustTransitive(attributes: number): boolean {
  return (attributes & TRUST_ATTRIBUTE_NON_TRANSITIVE) === 0;
}

/**
 * Parse trust attributes to extract all security-relevant properties
 */
export function parseTrustAttributes(attributes: number): {
  sidFilteringEnabled: boolean;
  selectiveAuthEnabled: boolean;
  isTransitive: boolean;
} {
  return {
    sidFilteringEnabled: isSidFilteringEnabled(attributes),
    selectiveAuthEnabled: isSelectiveAuthEnabled(attributes),
    isTransitive: isTrustTransitive(attributes),
  };
}
