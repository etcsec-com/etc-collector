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

import { ADUser, ADGroup, ADDomain } from '../../../../types/ad.types';
import { Finding } from '../../../../types/finding.types';
import { toAffectedUserEntities } from '../../../../utils/entity-converter';
import { GpoSecuritySettings } from '../../../../providers/smb/smb.provider';

/**
 * Extended GPO settings for monitoring analysis
 */
export interface MonitoringGpoSettings extends GpoSecuritySettings {
  /** Event log maximum size settings (in KB) */
  eventLogSettings?: {
    securityLogMaxSize?: number;
    systemLogMaxSize?: number;
    applicationLogMaxSize?: number;
  };
}

/**
 * Detect if logon events are not being audited
 * Checks for "Account Logon" and "Logon/Logoff" audit categories
 */
export function detectAuditLogonEventsDisabled(
  gpoSettings: GpoSecuritySettings | null,
  domain: ADDomain | null,
  includeDetails: boolean
): Finding {
  if (gpoSettings?.auditPolicies && gpoSettings.auditPolicies.length > 0) {
    const auditPolicies = gpoSettings.auditPolicies;

    // Check for logon-related audit categories
    const logonCategories = ['Account Logon', 'Logon/Logoff', 'Logon'];
    const hasLogonAudit = auditPolicies.some(
      (p) => logonCategories.some((cat) => p.category.includes(cat)) && (p.success || p.failure)
    );

    return {
      type: 'AUDIT_LOGON_EVENTS_DISABLED',
      severity: 'high',
      category: 'monitoring',
      title: 'Logon Events Not Audited',
      description:
        'Logon events are not being audited. Failed and successful authentication attempts will not be logged, hindering intrusion detection.',
      count: hasLogonAudit ? 0 : 1,
      affectedEntities: includeDetails && !hasLogonAudit && domain ? [domain.dn] : undefined,
      details: !hasLogonAudit
        ? {
            recommendation:
              'Enable "Audit Logon Events" and "Audit Account Logon Events" for both Success and Failure.',
            missingCategories: logonCategories,
            attacksUndetected: [
              'Brute force attacks',
              'Password spraying',
              'Pass-the-hash',
              'Kerberos ticket attacks',
            ],
          }
        : undefined,
    };
  }

  return {
    type: 'AUDIT_LOGON_EVENTS_DISABLED',
    severity: 'high',
    category: 'monitoring',
    title: 'Logon Audit Configuration Unknown',
    description: 'Unable to determine logon audit configuration. Manual review recommended.',
    count: 0,
    details: {
      note: 'GPO audit settings not available. Check Advanced Audit Policy Configuration manually.',
    },
  };
}

/**
 * Detect if account management events are not being audited
 */
export function detectAuditAccountMgmtDisabled(
  gpoSettings: GpoSecuritySettings | null,
  domain: ADDomain | null,
  includeDetails: boolean
): Finding {
  if (gpoSettings?.auditPolicies && gpoSettings.auditPolicies.length > 0) {
    const auditPolicies = gpoSettings.auditPolicies;

    const hasAccountMgmtAudit = auditPolicies.some(
      (p) => p.category.includes('Account Management') && (p.success || p.failure)
    );

    return {
      type: 'AUDIT_ACCOUNT_MGMT_DISABLED',
      severity: 'high',
      category: 'monitoring',
      title: 'Account Management Not Audited',
      description:
        'Account management events are not being audited. User/group creation, modification, and deletion will not be logged.',
      count: hasAccountMgmtAudit ? 0 : 1,
      affectedEntities: includeDetails && !hasAccountMgmtAudit && domain ? [domain.dn] : undefined,
      details: !hasAccountMgmtAudit
        ? {
            recommendation: 'Enable "Audit Account Management" for both Success and Failure.',
            attacksUndetected: [
              'Unauthorized account creation',
              'Privilege escalation via group membership',
              'Backdoor accounts',
              'Account takeover',
            ],
          }
        : undefined,
    };
  }

  return {
    type: 'AUDIT_ACCOUNT_MGMT_DISABLED',
    severity: 'high',
    category: 'monitoring',
    title: 'Account Management Audit Configuration Unknown',
    description: 'Unable to determine account management audit configuration.',
    count: 0,
  };
}

/**
 * Detect if policy change events are not being audited
 */
export function detectAuditPolicyChangeDisabled(
  gpoSettings: GpoSecuritySettings | null,
  domain: ADDomain | null,
  includeDetails: boolean
): Finding {
  if (gpoSettings?.auditPolicies && gpoSettings.auditPolicies.length > 0) {
    const auditPolicies = gpoSettings.auditPolicies;

    const hasPolicyChangeAudit = auditPolicies.some(
      (p) => p.category.includes('Policy Change') && (p.success || p.failure)
    );

    return {
      type: 'AUDIT_POLICY_CHANGE_DISABLED',
      severity: 'high',
      category: 'monitoring',
      title: 'Policy Changes Not Audited',
      description:
        'Policy change events are not being audited. GPO modifications and security policy changes will not be logged.',
      count: hasPolicyChangeAudit ? 0 : 1,
      affectedEntities: includeDetails && !hasPolicyChangeAudit && domain ? [domain.dn] : undefined,
      details: !hasPolicyChangeAudit
        ? {
            recommendation: 'Enable "Audit Policy Change" for both Success and Failure.',
            attacksUndetected: [
              'GPO poisoning',
              'Security policy weakening',
              'Audit policy tampering',
              'Firewall rule modifications',
            ],
          }
        : undefined,
    };
  }

  return {
    type: 'AUDIT_POLICY_CHANGE_DISABLED',
    severity: 'high',
    category: 'monitoring',
    title: 'Policy Change Audit Configuration Unknown',
    description: 'Unable to determine policy change audit configuration.',
    count: 0,
  };
}

/**
 * Detect if privilege use is not being audited
 */
export function detectAuditPrivilegeUseDisabled(
  gpoSettings: GpoSecuritySettings | null,
  domain: ADDomain | null,
  includeDetails: boolean
): Finding {
  if (gpoSettings?.auditPolicies && gpoSettings.auditPolicies.length > 0) {
    const auditPolicies = gpoSettings.auditPolicies;

    const hasPrivilegeUseAudit = auditPolicies.some(
      (p) => p.category.includes('Privilege Use') && (p.success || p.failure)
    );

    return {
      type: 'AUDIT_PRIVILEGE_USE_DISABLED',
      severity: 'medium',
      category: 'monitoring',
      title: 'Privilege Use Not Audited',
      description:
        'Privilege use events are not being audited. Sensitive privilege usage will not be logged.',
      count: hasPrivilegeUseAudit ? 0 : 1,
      affectedEntities: includeDetails && !hasPrivilegeUseAudit && domain ? [domain.dn] : undefined,
      details: !hasPrivilegeUseAudit
        ? {
            recommendation: 'Enable "Audit Privilege Use" for Failure events at minimum.',
            attacksUndetected: [
              'Privilege abuse',
              'SeDebugPrivilege exploitation',
              'Token manipulation',
              'Impersonation attacks',
            ],
          }
        : undefined,
    };
  }

  return {
    type: 'AUDIT_PRIVILEGE_USE_DISABLED',
    severity: 'medium',
    category: 'monitoring',
    title: 'Privilege Use Audit Configuration Unknown',
    description: 'Unable to determine privilege use audit configuration.',
    count: 0,
  };
}

/**
 * Detect absence of honeypot/decoy accounts
 * Honeypots help detect attackers early during enumeration
 */
export function detectNoHoneypotAccounts(users: ADUser[], _includeDetails: boolean): Finding {
  const honeypotPatterns = ['honeypot', 'decoy', 'trap', 'canary', 'bait', 'fake'];
  const attractivePatterns = ['svc_', 'admin_backup', 'admin_old', 'sa_', 'sqlsvc', 'backup_admin'];

  // Find explicit honeypot accounts
  const honeypots = users.filter((u) => {
    const rawDesc = u.description;
    const desc = (typeof rawDesc === 'string' ? rawDesc : '').toLowerCase();
    const name = (u.sAMAccountName || '').toLowerCase();
    return honeypotPatterns.some((p) => desc.includes(p) || name.includes(p));
  });

  // Find potential bait accounts (attractive names, never used)
  const potentialBaits = users.filter((u) => {
    const name = (u.sAMAccountName || '').toLowerCase();
    const hasAttractiveNaming = attractivePatterns.some((p) => name.includes(p));
    const neverLoggedIn = !u.lastLogon;
    const isEnabled = u.enabled;
    return hasAttractiveNaming && neverLoggedIn && isEnabled;
  });

  const hasHoneypots = honeypots.length > 0 || potentialBaits.length >= 2;

  return {
    type: 'NO_HONEYPOT_ACCOUNTS',
    severity: 'medium',
    category: 'monitoring',
    title: 'No Honeypot/Decoy Accounts Detected',
    description:
      'No honeypot or decoy accounts detected in the directory. These accounts help detect attackers during enumeration phase.',
    count: hasHoneypots ? 0 : 1,
    affectedEntities: undefined, // No affected entities - this is a missing control
    details: hasHoneypots
      ? {
          honeypotCount: honeypots.length,
          potentialBaitCount: potentialBaits.length,
          status: 'Honeypot accounts detected',
        }
      : {
          recommendation:
            'Create honeypot accounts with attractive names (e.g., svc_backup, admin_old) and monitor for any usage.',
          benefits: [
            'Early detection of attacker enumeration',
            'Detect credential stuffing attempts',
            'Alert on lateral movement',
          ],
          implementationGuide:
            'Create accounts with attractive names but no real permissions. Alert on any authentication attempt.',
        },
  };
}

/**
 * Detect if admins can bypass audit
 * Checks for accounts with SeAuditPrivilege or audit bypass capabilities
 */
export function detectAdminAuditBypass(
  users: ADUser[],
  _domain: ADDomain | null,
  includeDetails: boolean
): Finding {
  // Find users with adminCount=1 who are not in Protected Users
  // These admins may have the ability to manipulate audit logs
  const adminUsers = users.filter((u) => u.adminCount === 1 && u.enabled);

  // Check for users not in Protected Users group
  const protectedUsersPattern = /protected users/i;
  const adminsNotProtected = adminUsers.filter((u) => {
    const memberOf = u['memberOf'] as string[] | undefined;
    if (!memberOf) return true;
    return !memberOf.some((g) => protectedUsersPattern.test(g));
  });

  // Check for specific concerning patterns
  const auditBypassRisk = adminsNotProtected.filter((u) => {
    // Admins with old passwords are higher risk (may be compromised)
    const pwdAge = u.pwdLastSet ? Date.now() - new Date(u.pwdLastSet).getTime() : Infinity;
    const pwdAgeMonths = pwdAge / (1000 * 60 * 60 * 24 * 30);
    return pwdAgeMonths > 6; // Password older than 6 months
  });

  const hasRisk = auditBypassRisk.length > 0;

  return {
    type: 'ADMIN_AUDIT_BYPASS',
    severity: 'high',
    category: 'monitoring',
    title: 'Administrators Can Bypass Audit',
    description:
      'Privileged accounts not in Protected Users group with old passwords may bypass audit controls.',
    count: auditBypassRisk.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(auditBypassRisk) : undefined,
    details: hasRisk
      ? {
          totalAdmins: adminUsers.length,
          adminsNotProtected: adminsNotProtected.length,
          adminsWithOldPasswords: auditBypassRisk.length,
          recommendation:
            'Add admin accounts to Protected Users group and enforce regular password rotation.',
          risks: [
            'Admins can clear security logs',
            'Compromised admin credentials may evade detection',
            'Audit policies may be disabled by compromised admin',
          ],
        }
      : undefined,
  };
}

/**
 * Detect if security log size is too small
 * Small logs mean events are overwritten quickly, losing forensic data
 */
export function detectSecurityLogSizeSmall(
  gpoSettings: MonitoringGpoSettings | null,
  domain: ADDomain | null,
  includeDetails: boolean
): Finding {
  const MINIMUM_LOG_SIZE_KB = 128 * 1024; // 128 MB minimum recommended

  if (gpoSettings?.eventLogSettings?.securityLogMaxSize !== undefined) {
    const logSize = gpoSettings.eventLogSettings.securityLogMaxSize;
    const isTooSmall = logSize < MINIMUM_LOG_SIZE_KB;

    return {
      type: 'SECURITY_LOG_SIZE_SMALL',
      severity: 'medium',
      category: 'monitoring',
      title: 'Security Log Size Insufficient',
      description: `Security event log maximum size is ${Math.round(logSize / 1024)} MB. Small logs cause events to be overwritten quickly, losing forensic data.`,
      count: isTooSmall ? 1 : 0,
      affectedEntities: includeDetails && isTooSmall && domain ? [domain.dn] : undefined,
      details: isTooSmall
        ? {
            currentSizeKB: logSize,
            currentSizeMB: Math.round(logSize / 1024),
            recommendedSizeKB: MINIMUM_LOG_SIZE_KB,
            recommendedSizeMB: Math.round(MINIMUM_LOG_SIZE_KB / 1024),
            recommendation: 'Increase Security log maximum size to at least 128 MB via GPO.',
            risks: [
              'Critical events may be lost due to log rotation',
              'Incident response hampered by missing events',
              'Compliance violations for log retention requirements',
            ],
          }
        : undefined,
    };
  }

  // Return informational finding if we can't determine log size
  // Don't count as a vulnerability since we can't verify
  return {
    type: 'SECURITY_LOG_SIZE_SMALL',
    severity: 'medium',
    category: 'monitoring',
    title: 'Security Log Size Configuration Unknown',
    description: 'Unable to determine security event log size configuration.',
    count: 0,
    details: {
      note: 'GPO event log settings not available. Verify Security log maximum size manually.',
      recommendedSizeMB: Math.round(MINIMUM_LOG_SIZE_KB / 1024),
    },
  };
}

/**
 * Detect if Protected Users group is not being used
 * Protected Users provides additional protections for privileged accounts
 */
export function detectNoProtectedUsersMonitoring(
  users: ADUser[],
  groups: ADGroup[],
  includeDetails: boolean
): Finding {
  // Find the Protected Users group
  const protectedUsersGroup = groups.find((g) => {
    const name = (g.sAMAccountName || g.displayName || '').toLowerCase();
    return name === 'protected users' || g.dn.toLowerCase().includes('cn=protected users');
  });

  // Get privileged users who should be in Protected Users
  const privilegedUsers = users.filter((u) => u.adminCount === 1 && u.enabled);

  // Check which privileged users are NOT in Protected Users
  const notInProtectedUsers = privilegedUsers.filter((u) => {
    const memberOf = u['memberOf'] as string[] | undefined;
    if (!memberOf) return true;

    // Check if any membership is Protected Users
    return !memberOf.some(
      (g) =>
        g.toLowerCase().includes('cn=protected users') ||
        (protectedUsersGroup && g.toLowerCase() === protectedUsersGroup.dn.toLowerCase())
    );
  });

  // If no Protected Users group found or it's empty
  const groupExists = protectedUsersGroup !== undefined;
  const groupMemberCount = protectedUsersGroup?.member?.length ?? 0;

  return {
    type: 'NO_PROTECTED_USERS_MONITORING',
    severity: 'medium',
    category: 'monitoring',
    title: 'Protected Users Group Not Utilized',
    description:
      'Privileged accounts are not members of the Protected Users group. This group provides additional protections against credential theft.',
    count: notInProtectedUsers.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(notInProtectedUsers) : undefined,
    details: {
      groupExists,
      currentMembers: groupMemberCount,
      totalPrivilegedAccounts: privilegedUsers.length,
      notInGroup: notInProtectedUsers.length,
      protections: [
        'NTLM authentication disabled',
        'Kerberos DES/RC4 encryption disabled',
        'Kerberos TGT lifetime reduced to 4 hours',
        'Credential delegation disabled',
        'Cached credentials not stored',
      ],
      recommendation:
        'Add all privileged/admin accounts to Protected Users group for enhanced credential protection.',
    },
  };
}

/**
 * Monitoring detector options
 */
export interface MonitoringDetectorOptions {
  /** GPO security settings including event log settings */
  gpoSettings?: MonitoringGpoSettings | null;
}

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
