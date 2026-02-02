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

import { ADUser } from '../../../../types/ad.types';
import { Finding } from '../../../../types/finding.types';
import { toAffectedUserEntities, ldapAttrToString } from '../../../../utils/entity-converter';

/**
 * Check for sensitive accounts with unconstrained delegation
 */
export function detectSensitiveDelegation(users: ADUser[], includeDetails: boolean): Finding {
  const privilegedGroups = [
    'Domain Admins',
    'Enterprise Admins',
    'Schema Admins',
    'Administrators',
  ];

  const affected = users.filter((u) => {
    if (!u.userAccountControl || !u.memberOf) return false;
    const hasUnconstrainedDeleg = (u.userAccountControl & 0x80000) !== 0;
    const isPrivileged = u.memberOf.some((dn) =>
      privilegedGroups.some((group) => dn.includes(`CN=${group}`))
    );
    return hasUnconstrainedDeleg && isPrivileged;
  });

  return {
    type: 'SENSITIVE_DELEGATION',
    severity: 'critical',
    category: 'accounts',
    title: 'Sensitive Account with Delegation',
    description: 'Privileged accounts (Domain/Enterprise Admins) with unconstrained delegation. Extreme security risk.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected) : undefined,
  };
}

/**
 * Check for disabled accounts still in admin groups
 */
export function detectDisabledAccountInAdminGroup(users: ADUser[], includeDetails: boolean): Finding {
  const adminGroups = ['Domain Admins', 'Enterprise Admins', 'Schema Admins'];

  const affected = users.filter((u) => {
    if (!u.userAccountControl || !u.memberOf) return false;
    const isDisabled = (u.userAccountControl & 0x2) !== 0;
    const isInAdminGroup = u.memberOf.some((dn) =>
      adminGroups.some((group) => dn.includes(`CN=${group}`))
    );
    return isDisabled && isInAdminGroup;
  });

  return {
    type: 'DISABLED_ACCOUNT_IN_ADMIN_GROUP',
    severity: 'high',
    category: 'accounts',
    title: 'Disabled Account in Admin Group',
    description: 'Disabled user accounts still present in privileged groups. Should be removed immediately.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected) : undefined,
  };
}

/**
 * Check for expired accounts still in admin groups
 */
export function detectExpiredAccountInAdminGroup(users: ADUser[], includeDetails: boolean): Finding {
  const adminGroups = ['Domain Admins', 'Enterprise Admins', 'Schema Admins'];
  const now = Date.now();

  const affected = users.filter((u) => {
    if (!u.memberOf) return false;
    const accountExpires = (u as any)['accountExpires'] as Date | undefined;
    const isExpired = accountExpires && accountExpires.getTime() < now;
    const isInAdminGroup = u.memberOf.some((dn: string) =>
      adminGroups.some((group) => dn.includes(`CN=${group}`))
    );
    return isExpired && isInAdminGroup;
  });

  return {
    type: 'EXPIRED_ACCOUNT_IN_ADMIN_GROUP',
    severity: 'high',
    category: 'accounts',
    title: 'Expired Account in Admin Group',
    description: 'Expired user accounts still present in privileged groups. Should be removed immediately.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected) : undefined,
  };
}

/**
 * Check for SID history attribute
 * Note: LDAP attribute name can vary in case (sIDHistory, sidhistory, etc.)
 */
export function detectSidHistory(users: ADUser[], includeDetails: boolean): Finding {
  const affected = users.filter((u) => {
    // Check multiple possible attribute names (case-insensitive)
    const userObj = u as Record<string, unknown>;
    const sidHistory =
      userObj['sIDHistory'] ??
      userObj['sidhistory'] ??
      userObj['SIDHistory'] ??
      userObj['sidHistory'];

    // Check if attribute exists and has value
    if (!sidHistory) return false;

    // Handle array or single value
    if (Array.isArray(sidHistory)) {
      return sidHistory.length > 0;
    }
    return !!sidHistory;
  });

  return {
    type: 'SID_HISTORY',
    severity: 'high',
    category: 'accounts',
    title: 'SID History Present',
    description: 'User accounts with sIDHistory attribute. Can be abused for privilege escalation.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected) : undefined,
  };
}

/**
 * Check for privileged accounts not in Protected Users group
 */
export function detectNotInProtectedUsers(users: ADUser[], includeDetails: boolean): Finding {
  const privilegedGroups = ['Domain Admins', 'Enterprise Admins', 'Schema Admins'];

  const affected = users.filter((u) => {
    if (!u.memberOf) return false;
    const isPrivileged = u.memberOf.some((dn) =>
      privilegedGroups.some((group) => dn.includes(`CN=${group}`))
    );
    const isInProtectedUsers = u.memberOf.some((dn) => dn.includes('CN=Protected Users'));
    return isPrivileged && !isInProtectedUsers;
  });

  return {
    type: 'NOT_IN_PROTECTED_USERS',
    severity: 'high',
    category: 'accounts',
    title: 'Not in Protected Users Group',
    description: 'Privileged accounts not in Protected Users group. Missing additional security protections.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected) : undefined,
  };
}

/**
 * Check for domain admin keywords in description
 */
export function detectDomainAdminInDescription(users: ADUser[], includeDetails: boolean): Finding {
  const sensitiveKeywords = [
    /domain\s*admin/i,
    /enterprise\s*admin/i,
    /administrator/i,
    /admin\s*account/i,
    /privileged/i,
  ];

  const affected = users.filter((u) => {
    const description = ldapAttrToString((u as any)['description']);
    if (!description) return false;
    return sensitiveKeywords.some((pattern) => pattern.test(description));
  });

  return {
    type: 'DOMAIN_ADMIN_IN_DESCRIPTION',
    severity: 'high',
    category: 'accounts',
    title: 'Sensitive Terms in Description',
    description: 'User accounts with admin/privileged keywords in description field. Information disclosure.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected) : undefined,
  };
}

/**
 * Check for Backup Operators membership
 */
export function detectBackupOperatorsMember(users: ADUser[], includeDetails: boolean): Finding {
  const affected = users.filter((u) => {
    if (!u.memberOf) return false;
    return u.memberOf.some((dn) => dn.includes('CN=Backup Operators'));
  });

  return {
    type: 'BACKUP_OPERATORS_MEMBER',
    severity: 'high',
    category: 'accounts',
    title: 'Backup Operators Member',
    description: 'Users in Backup Operators group. Can backup/restore files and bypass ACLs.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected) : undefined,
  };
}

/**
 * Check for Account Operators membership
 */
export function detectAccountOperatorsMember(users: ADUser[], includeDetails: boolean): Finding {
  const affected = users.filter((u) => {
    if (!u.memberOf) return false;
    return u.memberOf.some((dn) => dn.includes('CN=Account Operators'));
  });

  return {
    type: 'ACCOUNT_OPERATORS_MEMBER',
    severity: 'high',
    category: 'accounts',
    title: 'Account Operators Member',
    description: 'Users in Account Operators group. Can create/modify user accounts.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected) : undefined,
  };
}

/**
 * Check for Server Operators membership
 */
export function detectServerOperatorsMember(users: ADUser[], includeDetails: boolean): Finding {
  const affected = users.filter((u) => {
    if (!u.memberOf) return false;
    return u.memberOf.some((dn) => dn.includes('CN=Server Operators'));
  });

  return {
    type: 'SERVER_OPERATORS_MEMBER',
    severity: 'high',
    category: 'accounts',
    title: 'Server Operators Member',
    description: 'Users in Server Operators group. Can manage domain controllers.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected) : undefined,
  };
}

/**
 * Check for Print Operators membership
 */
export function detectPrintOperatorsMember(users: ADUser[], includeDetails: boolean): Finding {
  const affected = users.filter((u) => {
    if (!u.memberOf) return false;
    return u.memberOf.some((dn) => dn.includes('CN=Print Operators'));
  });

  return {
    type: 'PRINT_OPERATORS_MEMBER',
    severity: 'high',
    category: 'accounts',
    title: 'Print Operators Member',
    description: 'Users in Print Operators group. Can load drivers and manage printers on DCs.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected) : undefined,
  };
}

/**
 * Check for inactive accounts (365+ days)
 */
export function detectInactive365Days(users: ADUser[], includeDetails: boolean): Finding {
  const now = Date.now();
  const oneYearAgo = now - 365 * 24 * 60 * 60 * 1000;

  const affected = users.filter((u) => {
    if (!u.lastLogon) return false;
    return u.lastLogon.getTime() < oneYearAgo;
  });

  return {
    type: 'INACTIVE_365_DAYS',
    severity: 'medium',
    category: 'accounts',
    title: 'Inactive 365+ Days',
    description: 'User accounts inactive for 365+ days. Should be disabled or deleted.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected) : undefined,
  };
}

/**
 * Check for stale accounts (180+ days inactive)
 * PingCastle: StaleAccount
 */
export function detectStaleAccount(users: ADUser[], includeDetails: boolean): Finding {
  const now = Date.now();
  const sixMonthsAgo = now - 180 * 24 * 60 * 60 * 1000;

  const affected = users.filter((u) => {
    // Must be enabled
    if (!u.enabled) return false;
    // Check if last logon is older than 180 days
    if (!u.lastLogon) return false;
    const lastLogonTime = u.lastLogon instanceof Date ? u.lastLogon.getTime() : new Date(u.lastLogon).getTime();
    if (isNaN(lastLogonTime)) return false;
    return lastLogonTime < sixMonthsAgo;
  });

  return {
    type: 'STALE_ACCOUNT',
    severity: 'high',
    category: 'accounts',
    title: 'Stale Account (180+ Days)',
    description: 'Enabled user accounts inactive for 180+ days. Stale accounts increase attack surface and should be reviewed.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected) : undefined,
  };
}

/**
 * Check for enabled accounts that have never logged on
 * Indicates orphaned, unused, or provisioning issues
 */
export function detectNeverLoggedOn(users: ADUser[], includeDetails: boolean): Finding {
  const affected = users.filter((u) => {
    // Must be enabled
    if (!u.enabled) return false;
    // Never logged on
    return !u.lastLogon;
  });

  return {
    type: 'NEVER_LOGGED_ON',
    severity: 'medium',
    category: 'accounts',
    title: 'Never Logged On',
    description:
      'Enabled user accounts that have never logged into the domain. May indicate orphaned accounts, provisioning issues, or unused accounts that should be disabled.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected) : undefined,
  };
}

/**
 * Convert Windows FILETIME to JavaScript Date
 * FILETIME: 100-nanosecond intervals since January 1, 1601
 */
function filetimeToDate(filetime: string | number | undefined): Date | null {
  if (!filetime) return null;
  const ft = typeof filetime === 'string' ? BigInt(filetime) : BigInt(filetime);
  // 0 or max value (never expires) should return null
  if (ft === BigInt(0) || ft === BigInt('9223372036854775807')) return null;
  // Convert to milliseconds since Unix epoch
  // FILETIME epoch is 1601-01-01, Unix epoch is 1970-01-01
  // Difference: 11644473600000 milliseconds
  const ms = Number(ft / BigInt(10000)) - 11644473600000;
  return new Date(ms);
}

/**
 * Check for accounts expiring within 30 days
 * Useful for proactive account management
 */
export function detectAccountExpireSoon(users: ADUser[], includeDetails: boolean): Finding {
  const now = Date.now();
  const thirtyDaysFromNow = now + 30 * 24 * 60 * 60 * 1000;

  const affected = users.filter((u) => {
    // Must be enabled
    if (!u.enabled) return false;
    // Check accountExpires
    const expiresDate = filetimeToDate(u.accountExpires);
    if (!expiresDate) return false; // Never expires
    // Expiring within 30 days but not already expired
    return expiresDate.getTime() > now && expiresDate.getTime() <= thirtyDaysFromNow;
  });

  return {
    type: 'ACCOUNT_EXPIRE_SOON',
    severity: 'medium',
    category: 'accounts',
    title: 'Account Expiring Soon',
    description:
      'User accounts set to expire within the next 30 days. Review if these expirations are intentional or if accounts need to be extended.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected) : undefined,
  };
}

/**
 * Check for admin accounts with very low logon count
 * May indicate unused admin accounts or recently created accounts with elevated privileges
 */
export function detectAdminLogonCountLow(users: ADUser[], includeDetails: boolean): Finding {
  const affected = users.filter((u) => {
    // Must be enabled
    if (!u.enabled) return false;
    // Must be marked as admin (adminCount = 1)
    if (u.adminCount !== 1) return false;
    // Check logon count (accessible via index signature)
    const logonCount = (u as any)['logonCount'] as number | undefined;
    // Low logon count (less than 5)
    return logonCount !== undefined && logonCount < 5;
  });

  return {
    type: 'ADMIN_LOGON_COUNT_LOW',
    severity: 'low',
    category: 'accounts',
    title: 'Admin Account with Low Logon Count',
    description:
      'Administrative accounts (adminCount=1) with fewer than 5 logons. May indicate unused privileged accounts that should be reviewed or disabled.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected) : undefined,
  };
}

/**
 * Check for test accounts
 */
export function detectTestAccount(users: ADUser[], includeDetails: boolean): Finding {
  const testPatterns = [/^test/i, /test$/i, /_test/i, /\.test/i, /^demo/i, /^temp/i];

  const affected = users.filter((u) => {
    return testPatterns.some((pattern) => pattern.test(u.sAMAccountName));
  });

  return {
    type: 'TEST_ACCOUNT',
    severity: 'medium',
    category: 'accounts',
    title: 'Test Account',
    description: 'User accounts with test/demo/temp naming. Should be removed from production.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected) : undefined,
  };
}

/**
 * Check for shared accounts
 */
export function detectSharedAccount(users: ADUser[], includeDetails: boolean): Finding {
  const sharedPatterns = [/^shared/i, /^common/i, /^generic/i, /^service/i, /^svc/i];

  const affected = users.filter((u) => {
    return sharedPatterns.some((pattern) => pattern.test(u.sAMAccountName));
  });

  return {
    type: 'SHARED_ACCOUNT',
    severity: 'medium',
    category: 'accounts',
    title: 'Shared Account',
    description: 'User accounts with shared/generic naming. Prevents proper accountability.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected) : undefined,
  };
}

/**
 * Check for accounts without smartcard requirement
 *
 * Detects enabled user accounts that don't have SMARTCARD_REQUIRED flag set.
 * In high-security environments, critical accounts should require smartcard.
 *
 * Note: This is a broad check. For admin-specific detection, use ADMIN_NO_SMARTCARD.
 * UAC flag 0x40000 = SMARTCARD_REQUIRED
 */
export function detectSmartcardNotRequired(users: ADUser[], includeDetails: boolean): Finding {
  // Only check enabled accounts with adminCount=1 (privileged accounts)
  // Regular users without smartcard is expected in most environments
  const affected = users.filter((u) => {
    if (!u.enabled) return false;
    if (!u.adminCount || u.adminCount !== 1) return false;

    const uac = u.userAccountControl || 0;
    // Check if SMARTCARD_REQUIRED is NOT set
    return (uac & 0x40000) === 0;
  });

  return {
    type: 'SMARTCARD_NOT_REQUIRED',
    severity: 'medium',
    category: 'accounts',
    title: 'Smartcard Not Required',
    description:
      'Privileged accounts (adminCount=1) without smartcard requirement. ' +
      'High-value accounts should require strong authentication.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected) : undefined,
  };
}

/**
 * Check for primaryGroupID spoofing
 */
export function detectPrimaryGroupIdSpoofing(users: ADUser[], includeDetails: boolean): Finding {
  const affected = users.filter((u) => {
    const primaryGroupId = (u as any).primaryGroupID;
    if (!primaryGroupId) return false;
    return primaryGroupId !== 513;
  });

  return {
    type: 'PRIMARYGROUPID_SPOOFING',
    severity: 'medium',
    category: 'accounts',
    title: 'primaryGroupID Spoofing',
    description: 'User accounts with non-standard primaryGroupID. Can be used to hide group membership.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected) : undefined,
  };
}

// ==================== SERVICE ACCOUNT DETECTORS ====================

/**
 * Service account naming patterns for detection
 */
const SERVICE_ACCOUNT_PATTERNS = [
  /^svc[_-]/i, // svc_xxx, svc-xxx
  /[_-]svc$/i, // xxx_svc, xxx-svc
  /^service[_-]/i, // service_xxx, service-xxx
  /[_-]service$/i, // xxx_service
  /^sa[_-]/i, // sa_xxx (service account prefix)
  /[_-]sa$/i, // xxx_sa
  /^app[_-]/i, // app_xxx (application account)
  /^sql[_-]/i, // sql_xxx (SQL service)
  /^iis[_-]/i, // iis_xxx (IIS service)
  /^web[_-]/i, // web_xxx
  /^batch[_-]/i, // batch_xxx
  /^task[_-]/i, // task_xxx
  /^job[_-]/i, // job_xxx
  /^daemon[_-]/i, // daemon_xxx
  /^agent[_-]/i, // agent_xxx
];

/**
 * Get service principal names from user (handles index signature)
 */
function getServicePrincipalNames(user: ADUser): string[] {
  const spn = (user as any)['servicePrincipalName'];
  if (!spn) return [];
  if (Array.isArray(spn)) return spn;
  return [spn as string];
}

/**
 * Check if user is a service account (has SPN or matches naming pattern)
 */
function isServiceAccount(user: ADUser): boolean {
  // Has SPN = definitely a service account
  const spns = getServicePrincipalNames(user);
  if (spns.length > 0) {
    return true;
  }
  // Matches service naming pattern
  return SERVICE_ACCOUNT_PATTERNS.some((pattern) => pattern.test(user.sAMAccountName));
}

/**
 * SERVICE_ACCOUNT_WITH_SPN: User accounts with Service Principal Name
 * Kerberoasting targets - attackers can request service tickets and crack them offline
 */
export function detectServiceAccountWithSpn(users: ADUser[], includeDetails: boolean): Finding {
  const affected = users.filter((u) => {
    // Must be enabled and have SPN
    const spns = getServicePrincipalNames(u);
    if (spns.length === 0) return false;
    // Exclude disabled accounts
    if (u.userAccountControl && (u.userAccountControl & 0x2) !== 0) return false;
    return true;
  });

  return {
    type: 'SERVICE_ACCOUNT_WITH_SPN',
    severity: 'medium',
    category: 'accounts',
    title: 'Service Account with SPN (Kerberoasting Target)',
    description:
      'User accounts with Service Principal Name configured. These accounts are targets for Kerberoasting attacks where attackers request TGS tickets and crack them offline.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected) : undefined,
    details:
      affected.length > 0
        ? {
            recommendation:
              'Use gMSA (Group Managed Service Accounts) instead. For existing accounts, ensure strong passwords (25+ chars) and regular rotation.',
            spnCount: affected.reduce((sum, u) => sum + getServicePrincipalNames(u).length, 0),
          }
        : undefined,
  };
}

/**
 * SERVICE_ACCOUNT_NAMING: Accounts matching service naming conventions
 */
export function detectServiceAccountNaming(users: ADUser[], includeDetails: boolean): Finding {
  const affected = users.filter((u) => {
    // Only accounts matching naming patterns but WITHOUT SPN
    // (accounts WITH SPN are covered by SERVICE_ACCOUNT_WITH_SPN)
    const spns = getServicePrincipalNames(u);
    if (spns.length > 0) return false;
    // Exclude disabled accounts
    if (u.userAccountControl && (u.userAccountControl & 0x2) !== 0) return false;
    return SERVICE_ACCOUNT_PATTERNS.some((pattern) => pattern.test(u.sAMAccountName));
  });

  return {
    type: 'SERVICE_ACCOUNT_NAMING',
    severity: 'low',
    category: 'accounts',
    title: 'Service Account by Naming Convention',
    description:
      'User accounts matching service account naming patterns (svc_, _svc, service, etc.) without SPN. Review if these are actual service accounts.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected) : undefined,
  };
}

/**
 * SERVICE_ACCOUNT_OLD_PASSWORD: Service accounts with old passwords
 * High risk - service account passwords should be rotated regularly
 */
export function detectServiceAccountOldPassword(users: ADUser[], includeDetails: boolean): Finding {
  const now = Date.now();
  const oneYearAgo = now - 365 * 24 * 60 * 60 * 1000;

  const affected = users.filter((u) => {
    // Must be a service account
    if (!isServiceAccount(u)) return false;
    // Must be enabled
    if (u.userAccountControl && (u.userAccountControl & 0x2) !== 0) return false;
    // Password must be older than 1 year
    if (!u.passwordLastSet) return true; // Never set = very old
    return u.passwordLastSet.getTime() < oneYearAgo;
  });

  return {
    type: 'SERVICE_ACCOUNT_OLD_PASSWORD',
    severity: 'high',
    category: 'accounts',
    title: 'Service Account with Old Password',
    description:
      'Service accounts with passwords not changed in over 1 year. These accounts are high-value targets and passwords should be rotated regularly.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected) : undefined,
    details:
      affected.length > 0
        ? {
            recommendation:
              'Rotate service account passwords every 90 days or migrate to gMSA for automatic password management.',
          }
        : undefined,
  };
}

/**
 * SERVICE_ACCOUNT_PRIVILEGED: Service accounts in privileged groups
 * Critical - service accounts should not be domain admins
 */
export function detectServiceAccountPrivileged(users: ADUser[], includeDetails: boolean): Finding {
  const privilegedGroups = [
    'Domain Admins',
    'Enterprise Admins',
    'Schema Admins',
    'Administrators',
    'Backup Operators',
    'Account Operators',
    'Server Operators',
  ];

  const affected = users.filter((u) => {
    // Must be a service account
    if (!isServiceAccount(u)) return false;
    // Must be enabled
    if (u.userAccountControl && (u.userAccountControl & 0x2) !== 0) return false;
    // Check if in privileged groups
    if (!u.memberOf) return false;
    return u.memberOf.some((dn) => privilegedGroups.some((group) => dn.includes(`CN=${group}`)));
  });

  return {
    type: 'SERVICE_ACCOUNT_PRIVILEGED',
    severity: 'critical',
    category: 'accounts',
    title: 'Service Account in Privileged Group',
    description:
      'Service accounts with membership in privileged groups (Domain Admins, etc.). If compromised, attackers gain full domain control.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected) : undefined,
    details:
      affected.length > 0
        ? {
            recommendation:
              'Remove service accounts from privileged groups. Grant only the minimum permissions needed for the service to function.',
          }
        : undefined,
  };
}

/**
 * SERVICE_ACCOUNT_NO_PREAUTH: Service accounts without Kerberos pre-authentication
 * AS-REP Roasting target
 */
export function detectServiceAccountNoPreauth(users: ADUser[], includeDetails: boolean): Finding {
  const DONT_REQUIRE_PREAUTH = 0x400000;

  const affected = users.filter((u) => {
    // Must be a service account
    if (!isServiceAccount(u)) return false;
    // Must be enabled
    if (!u.userAccountControl) return false;
    if ((u.userAccountControl & 0x2) !== 0) return false;
    // Check for "Do not require Kerberos preauthentication"
    return (u.userAccountControl & DONT_REQUIRE_PREAUTH) !== 0;
  });

  return {
    type: 'SERVICE_ACCOUNT_NO_PREAUTH',
    severity: 'high',
    category: 'accounts',
    title: 'Service Account Without Pre-Authentication (AS-REP Roasting)',
    description:
      'Service accounts with "Do not require Kerberos pre-authentication" enabled. Attackers can request AS-REP tickets and crack them offline.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected) : undefined,
    details:
      affected.length > 0
        ? {
            recommendation: 'Enable Kerberos pre-authentication for all service accounts.',
          }
        : undefined,
  };
}

/**
 * SERVICE_ACCOUNT_WEAK_ENCRYPTION: Service accounts using weak Kerberos encryption
 */
export function detectServiceAccountWeakEncryption(users: ADUser[], includeDetails: boolean): Finding {
  // msDS-SupportedEncryptionTypes bit flags
  // 0x1 = DES-CBC-CRC, 0x2 = DES-CBC-MD5 (both weak)
  // 0x4 = RC4-HMAC (weak), 0x8 = AES128, 0x10 = AES256

  const affected = users.filter((u) => {
    // Must be a service account
    if (!isServiceAccount(u)) return false;
    // Must be enabled
    if (u.userAccountControl && (u.userAccountControl & 0x2) !== 0) return false;

    const encTypes = (u as any)['msDS-SupportedEncryptionTypes'];
    if (!encTypes) return false;

    const encTypesNum = typeof encTypes === 'string' ? parseInt(encTypes, 10) : encTypes;
    // Check if only weak encryption types are enabled (DES or RC4 only, no AES)
    const hasOnlyWeak = (encTypesNum & 0x7) !== 0 && (encTypesNum & 0x18) === 0;
    return hasOnlyWeak;
  });

  return {
    type: 'SERVICE_ACCOUNT_WEAK_ENCRYPTION',
    severity: 'medium',
    category: 'accounts',
    title: 'Service Account Using Weak Kerberos Encryption',
    description:
      'Service accounts configured to use only weak Kerberos encryption (DES/RC4) without AES. Makes offline cracking easier.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected) : undefined,
    details:
      affected.length > 0
        ? {
            recommendation: 'Enable AES128 and AES256 encryption for all service accounts.',
          }
        : undefined,
  };
}

// ==================== PHASE 2C DETECTORS ====================

/**
 * Detect orphaned adminCount flag
 * Users with adminCount=1 but not actually in any admin group
 */
export function detectAdminCountOrphaned(users: ADUser[], includeDetails: boolean): Finding {
  const adminGroups = [
    'Domain Admins',
    'Enterprise Admins',
    'Schema Admins',
    'Administrators',
    'Account Operators',
    'Server Operators',
    'Backup Operators',
    'Print Operators',
  ];

  const affected = users.filter((u) => {
    // Must have adminCount=1
    if (u.adminCount !== 1) return false;

    // Check if actually in an admin group
    const memberOf = u['memberOf'] as string[] | undefined;
    if (!memberOf || memberOf.length === 0) return true; // adminCount but no group membership

    const isInAdminGroup = memberOf.some((dn) =>
      adminGroups.some((group) => dn.toLowerCase().includes(`cn=${group.toLowerCase()}`))
    );

    return !isInAdminGroup; // adminCount=1 but not in admin group
  });

  return {
    type: 'ADMIN_COUNT_ORPHANED',
    severity: 'medium',
    category: 'accounts',
    title: 'Orphaned AdminCount Flag',
    description:
      'Accounts with adminCount=1 but not in any privileged group. This may indicate removed admins that still have residual privileges or SDProp protection.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected) : undefined,
    details:
      affected.length > 0
        ? {
            recommendation:
              'Review these accounts. If no longer admins, clear adminCount flag and reset ACLs to allow proper inheritance.',
            impact: 'Accounts may still have protected ACLs preventing proper management.',
          }
        : undefined,
  };
}

/**
 * Detect privileged accounts with SPNs (kerberoastable)
 * Admin accounts should NOT have SPNs as they become kerberoasting targets
 */
export function detectPrivilegedAccountSpn(users: ADUser[], includeDetails: boolean): Finding {
  const affected = users.filter((u) => {
    // Must be privileged (adminCount=1)
    if (u.adminCount !== 1) return false;
    // Must be enabled
    if (!u.enabled) return false;

    // Must have SPN
    const spn = u['servicePrincipalName'];
    const hasSPN = spn && Array.isArray(spn) && spn.length > 0;

    return hasSPN;
  });

  return {
    type: 'PRIVILEGED_ACCOUNT_SPN',
    severity: 'high',
    category: 'accounts',
    title: 'Privileged Account with SPN',
    description:
      'Privileged accounts (adminCount=1) have Service Principal Names configured. These accounts are vulnerable to Kerberoasting attacks.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected) : undefined,
    details:
      affected.length > 0
        ? {
            attackVector: 'Request TGS ticket → Offline crack password → Full admin access',
            recommendation:
              'Remove SPNs from admin accounts. Use dedicated service accounts (preferably gMSA) for services.',
            criticalRisk: 'Compromising these accounts grants immediate Domain Admin or equivalent access.',
          }
        : undefined,
  };
}

/**
 * Detect admin accounts without smartcard requirement
 * Privileged accounts should require smartcard authentication
 */
export function detectAdminNoSmartcard(users: ADUser[], includeDetails: boolean): Finding {
  const affected = users.filter((u) => {
    // Must be privileged (adminCount=1)
    if (u.adminCount !== 1) return false;
    // Must be enabled
    if (!u.enabled) return false;

    // Check SMARTCARD_REQUIRED flag (0x40000)
    const smartcardRequired = u.userAccountControl ? (u.userAccountControl & 0x40000) !== 0 : false;

    return !smartcardRequired;
  });

  return {
    type: 'ADMIN_NO_SMARTCARD',
    severity: 'medium',
    category: 'accounts',
    title: 'Admin Account Without Smartcard Requirement',
    description:
      'Privileged accounts can authenticate with passwords instead of smartcards. Passwords are more vulnerable to theft and phishing.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected) : undefined,
    details:
      affected.length > 0
        ? {
            recommendation:
              'Enable "Smart card is required for interactive logon" for all admin accounts.',
            benefits: [
              'Eliminates password-based attacks (phishing, credential theft)',
              'Provides two-factor authentication',
              'Reduces risk of credential replay attacks',
            ],
          }
        : undefined,
  };
}

/**
 * Detect service accounts with interactive logon capability
 * Service accounts should be denied interactive logon
 */
export function detectServiceAccountInteractive(users: ADUser[], includeDetails: boolean): Finding {
  const affected = users.filter((u) => {
    // Must be a service account (has SPN or matches naming pattern)
    const spn = u['servicePrincipalName'];
    const hasSPN = spn && Array.isArray(spn) && spn.length > 0;
    const servicePatterns = [/^svc[_-]/i, /^sa[_-]/i, /service/i, /^sql/i, /^iis/i, /^app/i];
    const matchesPattern = servicePatterns.some((p) => p.test(u.sAMAccountName || ''));

    if (!hasSPN && !matchesPattern) return false;

    // Must be enabled
    if (!u.enabled) return false;

    // Check if interactive logon is NOT denied
    // A service account should have "Deny log on locally" and "Deny log on through RDP"
    // We check if the account has logged on recently (indicating interactive use)
    // or if it doesn't have restrictions that would prevent interactive logon

    // If the account has adminCount=0 (not protected by SDProp) and has recent logons
    // it's likely being used interactively
    const lastLogonStr = u.lastLogon;
    if (lastLogonStr) {
      const lastLogon = new Date(lastLogonStr);
      const daysSinceLogon = (Date.now() - lastLogon.getTime()) / (1000 * 60 * 60 * 24);
      // If logged on in last 30 days, may be used interactively
      if (daysSinceLogon < 30) {
        return true;
      }
    }

    // Also flag if password is set to never expire but account can logon interactively
    const pwdNeverExpires = u.userAccountControl ? (u.userAccountControl & 0x10000) !== 0 : false;
    const notDelegated = u.userAccountControl ? (u.userAccountControl & 0x100000) !== 0 : false;

    // Service accounts with password never expires but NOT marked as "not delegated" are risky
    return pwdNeverExpires && !notDelegated;
  });

  return {
    type: 'SERVICE_ACCOUNT_INTERACTIVE',
    severity: 'high',
    category: 'accounts',
    title: 'Service Account with Interactive Logon',
    description:
      'Service accounts appear to allow or use interactive logon. Service accounts should be restricted to service-only authentication.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected) : undefined,
    details:
      affected.length > 0
        ? {
            recommendation:
              'Apply "Deny log on locally" and "Deny log on through Remote Desktop Services" rights. Use gMSA where possible.',
            risks: [
              'Interactive sessions leave credentials in memory (mimikatz target)',
              'Increases attack surface for credential theft',
              'May indicate misuse of service accounts',
            ],
          }
        : undefined,
  };
}

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
 * Detect accounts with directory replication rights (DCSync risk)
 *
 * Users with DS-Replication-Get-Changes and DS-Replication-Get-Changes-All
 * can perform DCSync attacks to extract password hashes.
 *
 * @param users - Array of AD users
 * @param includeDetails - Whether to include affected entity details
 * @returns Finding for REPLICA_DIRECTORY_CHANGES
 */
export function detectReplicaDirectoryChanges(users: ADUser[], includeDetails: boolean): Finding {
  // This detection primarily works with ACL data, but we can check for
  // users in groups that typically have replication rights
  const replicationGroups = [
    'Domain Controllers',
    'Enterprise Domain Controllers',
    'Administrators',
    'Domain Admins',
    'Enterprise Admins',
  ];

  // Non-admin users that might have replication rights through delegation
  const affected = users.filter((u) => {
    if (!u.enabled || !u.memberOf) return false;
    // Check if user is in a group that shouldn't have replication rights
    // but description or other fields suggest replication permissions
    const rawDesc = (u as Record<string, unknown>)['description'];
    const description = typeof rawDesc === 'string' ? rawDesc : (Array.isArray(rawDesc) ? rawDesc[0] : '') || '';
    const hasReplicationHint =
      description.toLowerCase().includes('replication') ||
      description.toLowerCase().includes('dcsync') ||
      description.toLowerCase().includes('directory sync');

    // Check for non-standard accounts with admin count (may have been delegated)
    const isServiceLike = /^(svc|service|sync|repl)/i.test(u.sAMAccountName);
    const hasAdminCount = u.adminCount === 1;
    const isInReplicationGroup = u.memberOf.some((dn) =>
      replicationGroups.some((g) => dn.toLowerCase().includes(g.toLowerCase()))
    );

    return hasReplicationHint || (isServiceLike && hasAdminCount && !isInReplicationGroup);
  });

  return {
    type: 'REPLICA_DIRECTORY_CHANGES',
    severity: 'critical',
    category: 'accounts',
    title: 'Potential Directory Replication Rights',
    description:
      'Accounts that may have directory replication rights (DCSync capability). ' +
      'These accounts can extract all password hashes from the domain.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected) : undefined,
    details: {
      recommendation:
        'Review ACLs on domain head for DS-Replication-Get-Changes rights. Only Domain Controllers should have this permission.',
    },
  };
}

/**
 * Detect accounts in dangerous built-in groups
 *
 * Groups like Cert Publishers, RAS and IAS Servers, etc. have elevated privileges
 * that are often overlooked.
 *
 * @param users - Array of AD users
 * @param includeDetails - Whether to include affected entity details
 * @returns Finding for DANGEROUS_BUILTIN_MEMBERSHIP
 */
export function detectDangerousBuiltinMembership(users: ADUser[], includeDetails: boolean): Finding {
  const dangerousGroups = [
    'Cert Publishers', // Can publish certificates
    'RAS and IAS Servers', // Network access
    'Windows Authorization Access Group', // Token manipulation
    'Terminal Server License Servers', // Remote access
    'Incoming Forest Trust Builders', // Trust manipulation
    'Performance Log Users', // Can access performance data
    'Performance Monitor Users', // Can monitor system
    'Distributed COM Users', // DCOM access
    'Remote Desktop Users', // RDP access
    'Network Configuration Operators', // Network config
    'Cryptographic Operators', // Crypto operations
    'Event Log Readers', // Security log access
    'Hyper-V Administrators', // VM control
    'Access Control Assistance Operators', // ACL modification
    'Remote Management Users', // WinRM access
  ];

  const affected = users.filter((u) => {
    if (!u.enabled || !u.memberOf) return false;
    return u.memberOf.some((dn) =>
      dangerousGroups.some((g) => dn.toLowerCase().includes(g.toLowerCase()))
    );
  });

  return {
    type: 'DANGEROUS_BUILTIN_MEMBERSHIP',
    severity: 'medium',
    category: 'accounts',
    title: 'Dangerous Built-in Group Membership',
    description:
      'User accounts with membership in overlooked but dangerous built-in groups. ' +
      'These groups grant elevated privileges that may allow privilege escalation.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected) : undefined,
    details: {
      dangerousGroups: dangerousGroups,
    },
  };
}

/**
 * Detect locked admin accounts
 *
 * Administrative accounts that are currently locked may indicate
 * ongoing attack attempts or credential compromise.
 *
 * @param users - Array of AD users
 * @param includeDetails - Whether to include affected entity details
 * @returns Finding for LOCKED_ACCOUNT_ADMIN
 */
export function detectLockedAccountAdmin(users: ADUser[], includeDetails: boolean): Finding {
  const adminGroups = [
    'Domain Admins',
    'Enterprise Admins',
    'Schema Admins',
    'Administrators',
    'Account Operators',
    'Server Operators',
    'Backup Operators',
  ];

  const affected = users.filter((u) => {
    if (!u.memberOf) return false;
    // Check if account is locked (lockoutTime != 0 or UAC flag 0x10)
    const isLocked =
      (u.lockoutTime && u.lockoutTime !== '0' && u.lockoutTime !== 0) ||
      (u.userAccountControl && (u.userAccountControl & 0x10) !== 0);

    const isAdmin = u.memberOf.some((dn) =>
      adminGroups.some((g) => dn.toLowerCase().includes(g.toLowerCase()))
    );

    return isLocked && isAdmin;
  });

  return {
    type: 'LOCKED_ACCOUNT_ADMIN',
    severity: 'high',
    category: 'accounts',
    title: 'Locked Administrative Account',
    description:
      'Administrative accounts that are currently locked out. ' +
      'May indicate password spray attacks or compromised credential attempts.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected) : undefined,
    details: {
      recommendation:
        'Investigate why these admin accounts are locked. Check security logs for failed authentication attempts.',
    },
  };
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
