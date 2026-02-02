/**
 * Monitoring and Security Supervision Detector
 *
 * Detects security monitoring gaps and supervision weaknesses in Active Directory.
 * Phase 2B: Monitoring Detection
 *
 * Vulnerabilities detected (8):
 * HIGH (4):
 * - AUDIT_LOGON_EVENTS_DISABLED: Logon events not audited
 * - AUDIT_ACCOUNT_MGMT_DISABLED: Account management not audited
 * - AUDIT_POLICY_CHANGE_DISABLED: Policy changes not audited
 * - ADMIN_AUDIT_BYPASS: Admins can bypass audit
 *
 * MEDIUM (4):
 * - AUDIT_PRIVILEGE_USE_DISABLED: Privilege use not audited
 * - NO_HONEYPOT_ACCOUNTS: No decoy accounts detected
 * - SECURITY_LOG_SIZE_SMALL: Security log size insufficient
 * - NO_PROTECTED_USERS_MONITORING: Protected Users group not used
 */

import { ADUser, ADGroup, ADDomain } from '../../../../../types/ad.types';
import { Finding } from '../../../../../types/finding.types';

// Re-export types
export { MonitoringGpoSettings, MonitoringDetectorOptions } from './types';

// Re-export individual detectors
export { detectAuditLogonEventsDisabled } from './audit-logon-events.detector';
export { detectAuditAccountMgmtDisabled } from './audit-account-mgmt.detector';
export { detectAuditPolicyChangeDisabled } from './audit-policy-change.detector';
export { detectAuditPrivilegeUseDisabled } from './audit-privilege-use.detector';
export { detectNoHoneypotAccounts } from './honeypot-accounts.detector';
export { detectAdminAuditBypass } from './admin-audit-bypass.detector';
export { detectSecurityLogSizeSmall } from './security-log-size.detector';
export { detectNoProtectedUsersMonitoring } from './protected-users.detector';

// Import for internal use
import { MonitoringDetectorOptions } from './types';
import { detectAuditLogonEventsDisabled } from './audit-logon-events.detector';
import { detectAuditAccountMgmtDisabled } from './audit-account-mgmt.detector';
import { detectAuditPolicyChangeDisabled } from './audit-policy-change.detector';
import { detectAuditPrivilegeUseDisabled } from './audit-privilege-use.detector';
import { detectNoHoneypotAccounts } from './honeypot-accounts.detector';
import { detectAdminAuditBypass } from './admin-audit-bypass.detector';
import { detectSecurityLogSizeSmall } from './security-log-size.detector';
import { detectNoProtectedUsersMonitoring } from './protected-users.detector';

/**
 * Detect all monitoring vulnerabilities
 */
export function detectMonitoringVulnerabilities(
  users: ADUser[],
  groups: ADGroup[],
  domain: ADDomain | null,
  includeDetails: boolean,
  options: MonitoringDetectorOptions = {}
): Finding[] {
  const { gpoSettings = null } = options;

  return [
    // High severity - Audit gaps
    detectAuditLogonEventsDisabled(gpoSettings, domain, includeDetails),
    detectAuditAccountMgmtDisabled(gpoSettings, domain, includeDetails),
    detectAuditPolicyChangeDisabled(gpoSettings, domain, includeDetails),
    detectAdminAuditBypass(users, domain, includeDetails),
    // Medium severity
    detectAuditPrivilegeUseDisabled(gpoSettings, domain, includeDetails),
    detectNoHoneypotAccounts(users, includeDetails),
    detectSecurityLogSizeSmall(gpoSettings, domain, includeDetails),
    detectNoProtectedUsersMonitoring(users, groups, includeDetails),
  ].filter((finding) => finding.count > 0);
}
