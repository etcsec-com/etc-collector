/**
 * Advanced Security Vulnerability Detector
 *
 * Detects advanced AD vulnerabilities including ADCS, LAPS, Shadow Credentials, RBCD, DCSync, etc.
 * Story 1.7: AD Vulnerability Detection Engine
 * Story 1.1: SMB & LDAP Signing Detection
 *
 * Vulnerabilities detected (36):
 * CRITICAL (5):
 * - SHADOW_CREDENTIALS
 * - RBCD_ABUSE
 * - EXCHANGE_PRIV_ESC_PATH - Phase 4
 * - LDAP_SIGNING_DISABLED - LDAP signing not required (Story 1.1)
 * - SMB_SIGNING_DISABLED - SMB signing not required (Story 1.1)
 *
 * HIGH (11):
 * - ESC1_VULNERABLE_TEMPLATE
 * - ESC2_ANY_PURPOSE
 * - ESC3_ENROLLMENT_AGENT
 * - ESC4_VULNERABLE_TEMPLATE_ACL
 * - ESC6_EDITF_ATTRIBUTESUBJECTALTNAME2
 * - LAPS_PASSWORD_READABLE
 * - REPLICATION_RIGHTS
 * - DCSYNC_CAPABLE
 * - MACHINE_ACCOUNT_QUOTA_HIGH - Quota > 10 (intentionally increased)
 * - LDAP_CHANNEL_BINDING_DISABLED - LDAP channel binding not required
 * - SMB_V1_ENABLED - SMBv1 protocol enabled
 * - ADMIN_SD_HOLDER_MODIFIED - Phase 4
 *
 * MEDIUM (17):
 * - ESC8_HTTP_ENROLLMENT
 * - LAPS_NOT_DEPLOYED
 * - LAPS_LEGACY_ATTRIBUTE
 * - DUPLICATE_SPN
 * - WEAK_PASSWORD_POLICY
 * - WEAK_KERBEROS_POLICY
 * - MACHINE_ACCOUNT_QUOTA_ABUSE
 * - DELEGATION_PRIVILEGE
 * - ADCS_WEAK_PERMISSIONS
 * - DANGEROUS_LOGON_SCRIPTS
 * - FOREIGN_SECURITY_PRINCIPALS
 * - NTLM_RELAY_OPPORTUNITY
 * - RECYCLE_BIN_DISABLED - AD Recycle Bin not enabled
 * - ANONYMOUS_LDAP_ACCESS - Anonymous LDAP bind allowed
 * - AUDIT_POLICY_WEAK - Audit policy incomplete
 * - POWERSHELL_LOGGING_DISABLED - PowerShell logging not configured
 * - DS_HEURISTICS_MODIFIED - Phase 4
 *
 * LOW (2):
 * - LAPS_PASSWORD_SET
 * - LAPS_PASSWORD_LEAKED
 */

import { ADUser, ADComputer, ADDomain } from '../../../../../types/ad.types';
import { Finding } from '../../../../../types/finding.types';

// Re-export types
export { GpoSecuritySettings, AdvancedDetectorOptions } from './types';

// Re-export all detectors
export * from './credentials';
export * from './adcs';
export * from './laps';
export * from './replication';
export * from './domain-policy';
export * from './signing';
export * from './monitoring';
export * from './other';

// Import for the main detection function
import { detectShadowCredentials, detectRbcdAbuse } from './credentials';
import {
  detectEsc1VulnerableTemplate,
  detectEsc2AnyPurpose,
  detectEsc3EnrollmentAgent,
  detectEsc4VulnerableTemplateAcl,
  detectEsc6EditfAttributeSubjectAltName2,
  detectEsc8HttpEnrollment,
  detectAdcsWeakPermissions,
} from './adcs';
import {
  detectLapsPasswordReadable,
  detectLapsNotDeployed,
  detectLapsLegacyAttribute,
  detectLapsPasswordSet,
  detectLapsPasswordLeaked,
} from './laps';
import { detectReplicationRights, detectDcsyncCapable, detectDuplicateSpn } from './replication';
import {
  detectWeakPasswordPolicy,
  detectWeakKerberosPolicy,
  detectMachineAccountQuotaAbuse,
  detectMachineAccountQuotaHigh,
} from './domain-policy';
import {
  detectLdapSigningDisabled,
  detectLdapChannelBindingDisabled,
  detectSmbSigningDisabled,
  detectSmbV1Enabled,
} from './signing';
import {
  detectRecycleBinDisabled,
  detectAnonymousLdapAccess,
  detectAuditPolicyWeak,
  detectPowershellLoggingDisabled,
} from './monitoring';
import {
  detectDelegationPrivilege,
  detectForeignSecurityPrincipals,
  detectNtlmRelayOpportunity,
  detectDangerousLogonScripts,
  detectDsHeuristicsModified,
  detectAdminSdHolderModified,
  detectExchangePrivEscPath,
} from './other';
import { AdvancedDetectorOptions } from './types';

/**
 * Detect all advanced vulnerabilities
 */
export function detectAdvancedVulnerabilities(
  users: ADUser[],
  computers: ADComputer[],
  domain: ADDomain | null,
  templates: any[] = [],
  cas: any[] = [],
  fsps: any[] = [],
  includeDetails: boolean,
  options: AdvancedDetectorOptions = {}
): Finding[] {
  const { gpoSettings = null, anonymousAccessAllowed = false } = options;

  return [
    // Critical
    detectShadowCredentials(users, includeDetails),
    detectRbcdAbuse(users, includeDetails),
    // Critical (GPO-based) - Story 1.1
    detectLdapSigningDisabled(gpoSettings, domain, includeDetails),
    detectSmbSigningDisabled(gpoSettings, domain, includeDetails),
    // High
    detectEsc1VulnerableTemplate(templates, includeDetails),
    detectEsc2AnyPurpose(templates, includeDetails),
    detectEsc3EnrollmentAgent(templates, includeDetails),
    detectEsc4VulnerableTemplateAcl(templates, includeDetails),
    detectEsc6EditfAttributeSubjectAltName2(cas, includeDetails),
    detectLapsPasswordReadable(computers, includeDetails),
    detectReplicationRights(users, includeDetails),
    detectDcsyncCapable(users, includeDetails),
    // High (domain)
    detectMachineAccountQuotaHigh(domain, includeDetails),
    // High (GPO-based)
    detectLdapChannelBindingDisabled(gpoSettings, domain, includeDetails),
    detectSmbV1Enabled(gpoSettings, domain, includeDetails),
    // Medium
    detectEsc8HttpEnrollment(cas, includeDetails),
    detectLapsNotDeployed(computers, includeDetails),
    detectLapsLegacyAttribute(computers, includeDetails),
    detectDuplicateSpn(users, includeDetails),
    detectWeakPasswordPolicy(domain, includeDetails),
    detectWeakKerberosPolicy(domain, includeDetails),
    detectMachineAccountQuotaAbuse(domain, includeDetails),
    detectDelegationPrivilege(users, includeDetails),
    detectForeignSecurityPrincipals(fsps, includeDetails),
    detectNtlmRelayOpportunity(domain, includeDetails),
    detectAdcsWeakPermissions(templates, includeDetails),
    detectDangerousLogonScripts(users, includeDetails),
    // Medium (Phase 1B)
    detectRecycleBinDisabled(domain, includeDetails),
    detectAnonymousLdapAccess(anonymousAccessAllowed, domain, includeDetails),
    detectAuditPolicyWeak(gpoSettings, domain, includeDetails),
    detectPowershellLoggingDisabled(gpoSettings, domain, includeDetails),
    // Low
    detectLapsPasswordSet(computers, includeDetails),
    detectLapsPasswordLeaked(computers, includeDetails),
    // Phase 4: Advanced detections
    detectDsHeuristicsModified(domain, includeDetails),
    detectAdminSdHolderModified(domain, includeDetails),
    detectExchangePrivEscPath(users, includeDetails),
  ].filter(
    (finding) =>
      finding.count > 0 ||
      // Always include critical signing findings (even with count=0) for visibility
      finding.type === 'SMB_SIGNING_DISABLED' ||
      finding.type === 'LDAP_SIGNING_DISABLED'
  );
}
