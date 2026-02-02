/**
 * ADCS (AD Certificate Services) Types
 *
 * Types for certificate templates and CAs used in ESC1-ESC11 vulnerability detection.
 */

/**
 * ADCS Certificate Template
 */
export interface ADCSCertificateTemplate {
  dn: string;
  name: string;
  displayName?: string;

  // Template OID
  'msPKI-Cert-Template-OID'?: string;

  // Flags
  'msPKI-Certificate-Name-Flag'?: number;
  'msPKI-Enrollment-Flag'?: number;
  'msPKI-Private-Key-Flag'?: number;
  'msPKI-RA-Signature'?: number;

  // Schema version (1 = legacy, 2+ = newer with security extension support)
  'msPKI-Template-Schema-Version'?: number;

  // Extended Key Usage OIDs
  pKIExtendedKeyUsage?: string[];

  // Security descriptor for ACL analysis
  nTSecurityDescriptor?: Buffer;

  // cn field (used for matching)
  cn?: string;
}

/**
 * ADCS Certificate Authority
 */
export interface ADCSCertificateAuthority {
  dn: string;
  name: string;
  dNSHostName: string;

  // CA configuration
  certificateTemplates?: string[];
  cACertificate?: Buffer;

  // Security descriptor
  nTSecurityDescriptor?: Buffer;
}

// Certificate Name Flags (msPKI-Certificate-Name-Flag)
export const CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 0x00000001;
export const CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME = 0x00010000;
export const CT_FLAG_SUBJECT_REQUIRE_DIRECTORY_PATH = 0x80000000;
export const CT_FLAG_SUBJECT_REQUIRE_COMMON_NAME = 0x40000000;
export const CT_FLAG_SUBJECT_REQUIRE_EMAIL = 0x20000000;
export const CT_FLAG_SUBJECT_REQUIRE_DNS_AS_CN = 0x10000000;
export const CT_FLAG_SUBJECT_ALT_REQUIRE_UPN = 0x02000000;
export const CT_FLAG_SUBJECT_ALT_REQUIRE_EMAIL = 0x04000000;
export const CT_FLAG_SUBJECT_ALT_REQUIRE_SPN = 0x00800000;
export const CT_FLAG_SUBJECT_ALT_REQUIRE_DIRECTORY_GUID = 0x01000000;
export const CT_FLAG_SUBJECT_ALT_REQUIRE_DNS = 0x08000000;
export const CT_FLAG_SUBJECT_ALT_REQUIRE_DOMAIN_DNS = 0x00400000;

// Enrollment Flags (msPKI-Enrollment-Flag)
export const CT_FLAG_INCLUDE_SYMMETRIC_ALGORITHMS = 0x00000001;
export const CT_FLAG_PEND_ALL_REQUESTS = 0x00000002; // Manager approval required
export const CT_FLAG_PUBLISH_TO_KRA_CONTAINER = 0x00000004;
export const CT_FLAG_PUBLISH_TO_DS = 0x00000008;
export const CT_FLAG_AUTO_ENROLLMENT_CHECK_USER_DS_CERTIFICATE = 0x00000010;
export const CT_FLAG_AUTO_ENROLLMENT = 0x00000020;
export const CT_FLAG_PREVIOUS_APPROVAL_VALIDATE_REENROLLMENT = 0x00000040;
export const CT_FLAG_USER_INTERACTION_REQUIRED = 0x00000100;
export const CT_FLAG_REMOVE_INVALID_CERTIFICATE_FROM_PERSONAL_STORE = 0x00000400;
export const CT_FLAG_ALLOW_ENROLL_ON_BEHALF_OF = 0x00000800;
export const CT_FLAG_ADD_OCSP_NOCHECK = 0x00001000;
export const CT_FLAG_ENABLE_KEY_REUSE_ON_NT_TOKEN_KEYSET_STORAGE_FULL = 0x00002000;
export const CT_FLAG_NOREVOCATIONINFOINISSUEDCERTS = 0x00004000;
export const CT_FLAG_INCLUDE_BASIC_CONSTRAINTS_FOR_EE_CERTS = 0x00008000;
export const CT_FLAG_ALLOW_PREVIOUS_APPROVAL_KEYBASEDRENEWAL_VALIDATE_REENROLLMENT = 0x00010000;
export const CT_FLAG_ISSUANCE_POLICIES_FROM_REQUEST = 0x00020000;

// Common Extended Key Usage OIDs
export const EKU_CLIENT_AUTH = '1.3.6.1.5.5.7.3.2';
export const EKU_PKIINIT_CLIENT_AUTH = '1.3.6.1.5.2.3.4';
export const EKU_SMART_CARD_LOGON = '1.3.6.1.4.1.311.20.2.2';
export const EKU_ANY_PURPOSE = '2.5.29.37.0';
export const EKU_CERTIFICATE_REQUEST_AGENT = '1.3.6.1.4.1.311.20.2.1'; // Enrollment Agent
export const EKU_SERVER_AUTH = '1.3.6.1.5.5.7.3.1';

/**
 * ESC vulnerability type enum
 */
export type ESCVulnerabilityType =
  | 'ESC1'
  | 'ESC2'
  | 'ESC3'
  | 'ESC4'
  | 'ESC5'
  | 'ESC6'
  | 'ESC7'
  | 'ESC8'
  | 'ESC9'
  | 'ESC10'
  | 'ESC11';
