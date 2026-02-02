/**
 * Accounts Security Vulnerability Detector
 *
 * Detects account-related vulnerabilities in AD.
 * Story 1.7: AD Vulnerability Detection Engine
 *
 * Vulnerabilities detected (31):
 *
 * PRIVILEGED ACCOUNTS:
 * - SENSITIVE_DELEGATION (Critical)
 * - DISABLED_ACCOUNT_IN_ADMIN_GROUP (High)
 * - EXPIRED_ACCOUNT_IN_ADMIN_GROUP (High)
 * - SID_HISTORY (High)
 * - NOT_IN_PROTECTED_USERS (High)
 * - DOMAIN_ADMIN_IN_DESCRIPTION (High)
 * - BACKUP_OPERATORS_MEMBER (High)
 * - ACCOUNT_OPERATORS_MEMBER (High)
 * - SERVER_OPERATORS_MEMBER (High)
 * - PRINT_OPERATORS_MEMBER (High)
 *
 * STATUS:
 * - INACTIVE_365_DAYS (Medium)
 * - NEVER_LOGGED_ON (Medium) - Enabled accounts that have never logged in
 * - ACCOUNT_EXPIRE_SOON (Medium) - Accounts expiring within 30 days
 * - ADMIN_LOGON_COUNT_LOW (Low) - Admin accounts with very few logons
 *
 * DANGEROUS PATTERNS:
 * - TEST_ACCOUNT (Medium)
 * - SHARED_ACCOUNT (Medium)
 * - SMARTCARD_NOT_REQUIRED (Medium)
 * - PRIMARYGROUPID_SPOOFING (Medium)
 *
 * SERVICE ACCOUNTS:
 * - SERVICE_ACCOUNT_WITH_SPN (Medium) - Kerberoasting targets
 * - SERVICE_ACCOUNT_NAMING (Low) - Accounts matching service naming patterns
 * - SERVICE_ACCOUNT_OLD_PASSWORD (High) - Passwords > 1 year old
 * - SERVICE_ACCOUNT_PRIVILEGED (Critical) - Service accounts in admin groups
 * - SERVICE_ACCOUNT_NO_PREAUTH (High) - AS-REP Roasting targets
 * - SERVICE_ACCOUNT_WEAK_ENCRYPTION (Medium) - DES/RC4 only encryption
 */

import { ADUser } from '../../../../../types/ad.types';
import { Finding } from '../../../../../types/finding.types';

// Re-export all individual detectors from subdirectories
export {
  detectSensitiveDelegation,
  detectDisabledAccountInAdminGroup,
  detectExpiredAccountInAdminGroup,
  detectSidHistory,
  detectNotInProtectedUsers,
  detectDomainAdminInDescription,
  detectBackupOperatorsMember,
  detectAccountOperatorsMember,
  detectServerOperatorsMember,
  detectPrintOperatorsMember,
} from './privileged';

export {
  detectStaleAccount,
  detectInactive365Days,
  detectNeverLoggedOn,
  detectAccountExpireSoon,
  detectAdminLogonCountLow,
  filetimeToDate,
} from './status';

export {
  detectTestAccount,
  detectSharedAccount,
  detectSmartcardNotRequired,
  detectPrimaryGroupIdSpoofing,
} from './patterns';

export {
  detectServiceAccountWithSpn,
  detectServiceAccountNaming,
  detectServiceAccountOldPassword,
  detectServiceAccountPrivileged,
  detectServiceAccountNoPreauth,
  detectServiceAccountWeakEncryption,
  detectServiceAccountInteractive,
  SERVICE_ACCOUNT_PATTERNS,
  getServicePrincipalNames,
  isServiceAccount,
} from './service-accounts';

export {
  detectAdminCountOrphaned,
  detectPrivilegedAccountSpn,
  detectAdminNoSmartcard,
  detectReplicaDirectoryChanges,
  detectDangerousBuiltinMembership,
  detectLockedAccountAdmin,
} from './advanced';

// Import for aggregate functions
import {
  detectSensitiveDelegation,
  detectDisabledAccountInAdminGroup,
  detectExpiredAccountInAdminGroup,
  detectSidHistory,
  detectNotInProtectedUsers,
  detectDomainAdminInDescription,
  detectBackupOperatorsMember,
  detectAccountOperatorsMember,
  detectServerOperatorsMember,
  detectPrintOperatorsMember,
} from './privileged';

import {
  detectStaleAccount,
  detectInactive365Days,
  detectNeverLoggedOn,
  detectAccountExpireSoon,
  detectAdminLogonCountLow,
} from './status';

import {
  detectTestAccount,
  detectSharedAccount,
  detectSmartcardNotRequired,
  detectPrimaryGroupIdSpoofing,
} from './patterns';

import {
  detectServiceAccountWithSpn,
  detectServiceAccountNaming,
  detectServiceAccountOldPassword,
  detectServiceAccountPrivileged,
  detectServiceAccountNoPreauth,
  detectServiceAccountWeakEncryption,
  detectServiceAccountInteractive,
} from './service-accounts';

import {
  detectAdminCountOrphaned,
  detectPrivilegedAccountSpn,
  detectAdminNoSmartcard,
  detectReplicaDirectoryChanges,
  detectDangerousBuiltinMembership,
  detectLockedAccountAdmin,
} from './advanced';

/**
 * Detect all service account related vulnerabilities
 */
export function detectServiceAccountVulnerabilities(users: ADUser[], includeDetails: boolean): Finding[] {
  return [
    detectServiceAccountWithSpn(users, includeDetails),
    detectServiceAccountNaming(users, includeDetails),
    detectServiceAccountOldPassword(users, includeDetails),
    detectServiceAccountPrivileged(users, includeDetails),
    detectServiceAccountNoPreauth(users, includeDetails),
    detectServiceAccountWeakEncryption(users, includeDetails),
  ].filter((finding) => finding.count > 0);
}

/**
 * Detect all account-related vulnerabilities
 */
export function detectAccountsVulnerabilities(users: ADUser[], includeDetails: boolean): Finding[] {
  return [
    // Privileged accounts detectors
    detectSensitiveDelegation(users, includeDetails),
    detectDisabledAccountInAdminGroup(users, includeDetails),
    detectExpiredAccountInAdminGroup(users, includeDetails),
    detectSidHistory(users, includeDetails),
    detectNotInProtectedUsers(users, includeDetails),
    detectDomainAdminInDescription(users, includeDetails),
    detectBackupOperatorsMember(users, includeDetails),
    detectAccountOperatorsMember(users, includeDetails),
    detectServerOperatorsMember(users, includeDetails),
    detectPrintOperatorsMember(users, includeDetails),
    // Status detectors
    detectStaleAccount(users, includeDetails),
    detectInactive365Days(users, includeDetails),
    detectNeverLoggedOn(users, includeDetails),
    detectAccountExpireSoon(users, includeDetails),
    detectAdminLogonCountLow(users, includeDetails),
    // Dangerous patterns
    detectTestAccount(users, includeDetails),
    detectSharedAccount(users, includeDetails),
    detectSmartcardNotRequired(users, includeDetails),
    detectPrimaryGroupIdSpoofing(users, includeDetails),
    // Service account detectors
    detectServiceAccountWithSpn(users, includeDetails),
    detectServiceAccountNaming(users, includeDetails),
    detectServiceAccountOldPassword(users, includeDetails),
    detectServiceAccountPrivileged(users, includeDetails),
    detectServiceAccountNoPreauth(users, includeDetails),
    detectServiceAccountWeakEncryption(users, includeDetails),
    // Phase 2C: Enhanced detections
    detectAdminCountOrphaned(users, includeDetails),
    detectPrivilegedAccountSpn(users, includeDetails),
    detectAdminNoSmartcard(users, includeDetails),
    detectServiceAccountInteractive(users, includeDetails),
    // Phase 4: Advanced detections
    detectReplicaDirectoryChanges(users, includeDetails),
    detectDangerousBuiltinMembership(users, includeDetails),
    detectLockedAccountAdmin(users, includeDetails),
  ].filter((finding) => finding.count > 0);
}
