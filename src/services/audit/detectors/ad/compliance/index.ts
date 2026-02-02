/**
 * Compliance Security Detector
 *
 * Detects security compliance violations based on ANSSI, NIST, CIS, DISA, and
 * industry frameworks (PCI-DSS, SOC2, GDPR, SOX, DORA, HIPAA, ISO27001).
 * Story 1.7: AD Vulnerability Detection Engine - Phase 3 + Compliance Frameworks
 *
 * Vulnerabilities detected (23):
 * - ANSSI_R1_PASSWORD_POLICY (High) - Password policy non-compliant with ANSSI R1
 * - ANSSI_R2_PRIVILEGED_ACCOUNTS (High) - Privileged accounts not compliant with ANSSI R2
 * - ANSSI_R3_STRONG_AUTH (Medium) - Strong authentication not enforced (ANSSI R3)
 * - ANSSI_R4_LOGGING (Medium) - Logging not compliant with ANSSI R4
 * - ANSSI_R5_SEGREGATION (Medium) - Network segregation issues (ANSSI R5)
 * - NIST_AC_2_ACCOUNT_MANAGEMENT (High) - Account management not compliant with NIST AC-2
 * - NIST_AC_6_LEAST_PRIVILEGE (High) - Least privilege violations (NIST AC-6)
 * - NIST_IA_5_AUTHENTICATOR (Medium) - Authenticator management issues (NIST IA-5)
 * - NIST_AU_2_AUDIT_EVENTS (Medium) - Audit events not configured (NIST AU-2)
 * - CIS_PASSWORD_POLICY (High) - Password policy not CIS compliant
 * - CIS_NETWORK_SECURITY (Medium) - Network security settings non-compliant
 * - CIS_USER_RIGHTS (Medium) - User rights assignment issues
 * - DISA_ACCOUNT_POLICIES (High) - Account policies not DISA STIG compliant
 * - DISA_AUDIT_POLICIES (High) - Audit policies not DISA STIG compliant
 * - MFA_NOT_ENFORCED (High) - Privileged accounts without MFA [PCI-DSS, SOC2]
 * - BACKUP_AD_NOT_VERIFIED (High) - No recent AD backup verification [SOC2, DORA]
 * - AUDIT_LOG_RETENTION_SHORT (High) - Log retention below required threshold [SOX, HIPAA]
 * - PRIVILEGED_ACCESS_REVIEW_MISSING (Medium) - No recent access review [SOX, ISO27001]
 * - DATA_CLASSIFICATION_MISSING (Medium) - OUs without data classification [GDPR, ISO27001]
 * - CHANGE_MANAGEMENT_BYPASS (High) - Changes outside approved process [SOX]
 * - VENDOR_ACCOUNT_UNMONITORED (Medium) - Third-party accounts not monitored [DORA]
 * - ENCRYPTION_AT_REST_DISABLED (High) - BitLocker not deployed on DCs [PCI-DSS, HIPAA]
 * - COMPLIANCE_SCORE (Info) - Overall compliance score summary
 */

import { ADUser, ADGroup, ADComputer, ADDomain } from '../../../../../types/ad.types';
import { Finding } from '../../../../../types/finding.types';
import { GpoSecuritySettings } from '../../../../../providers/smb/smb.provider';

// Re-export types
export { PasswordPolicy, FrameworkScore } from './types';

// Re-export all detectors
export * from './anssi';
export * from './nist';
export * from './cis';
export * from './disa';
export * from './industry';
export { detectComplianceScore } from './score';

// Import for the main detection function
import {
  detectAnssiR1PasswordPolicy,
  detectAnssiR2PrivilegedAccounts,
  detectAnssiR3StrongAuth,
  detectAnssiR4Logging,
  detectAnssiR5Segregation,
} from './anssi';
import {
  detectNistAc2AccountManagement,
  detectNistAc6LeastPrivilege,
  detectNistIa5Authenticator,
  detectNistAu2AuditEvents,
} from './nist';
import {
  detectCisPasswordPolicy,
  detectCisNetworkSecurity,
  detectCisUserRights,
} from './cis';
import {
  detectDisaAccountPolicies,
  detectDisaAuditPolicies,
} from './disa';
import {
  detectMfaNotEnforced,
  detectBackupNotVerified,
  detectAuditLogRetentionShort,
  detectPrivilegedAccessReviewMissing,
  detectDataClassificationMissing,
  detectChangeManagementBypass,
  detectVendorAccountUnmonitored,
  detectEncryptionAtRestDisabled,
} from './industry';
import { detectComplianceScore } from './score';

/**
 * Detect all compliance vulnerabilities
 */
export function detectComplianceVulnerabilities(
  users: ADUser[],
  groups: ADGroup[],
  computers: ADComputer[],
  domain: ADDomain,
  gpoSettings: GpoSecuritySettings | null,
  includeDetails: boolean
): Finding[] {
  // Collect all compliance findings except the score
  const findings = [
    // ANSSI
    detectAnssiR1PasswordPolicy(domain, gpoSettings, includeDetails),
    detectAnssiR2PrivilegedAccounts(users, groups, includeDetails),
    detectAnssiR3StrongAuth(users, domain, includeDetails),
    detectAnssiR4Logging(gpoSettings, includeDetails),
    detectAnssiR5Segregation(users, computers, includeDetails),
    // NIST
    detectNistAc2AccountManagement(users, includeDetails),
    detectNistAc6LeastPrivilege(users, groups, includeDetails),
    detectNistIa5Authenticator(domain, users, includeDetails),
    detectNistAu2AuditEvents(gpoSettings, includeDetails),
    // CIS
    detectCisPasswordPolicy(domain, includeDetails),
    detectCisNetworkSecurity(gpoSettings, includeDetails),
    detectCisUserRights(users, groups, includeDetails),
    // DISA
    detectDisaAccountPolicies(domain, users, includeDetails),
    detectDisaAuditPolicies(gpoSettings, includeDetails),
    // Industry Frameworks (PCI-DSS, SOC2, GDPR, SOX, DORA, HIPAA, ISO27001)
    detectMfaNotEnforced(users, includeDetails),
    detectBackupNotVerified(domain, includeDetails),
    detectAuditLogRetentionShort(gpoSettings, includeDetails),
    detectPrivilegedAccessReviewMissing(users, groups, includeDetails),
    detectDataClassificationMissing(domain, includeDetails),
    detectChangeManagementBypass(users, groups, includeDetails),
    detectVendorAccountUnmonitored(users, includeDetails),
    detectEncryptionAtRestDisabled(computers, includeDetails),
  ];

  // Add compliance score (calculated from other findings)
  findings.push(detectComplianceScore(findings, includeDetails));

  // Return all findings (including those with count=0 for score calculation)
  // But filter out zero-count findings for the final output
  return findings.filter((f) => f.count > 0 || f.type === 'COMPLIANCE_SCORE');
}
