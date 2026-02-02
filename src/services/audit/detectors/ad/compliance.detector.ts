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

import { ADUser, ADGroup, ADComputer, ADDomain } from '../../../../types/ad.types';
import { Finding } from '../../../../types/finding.types';
import { toAffectedUserEntities, ldapAttrToString } from '../../../../utils/entity-converter';
import { GpoSecuritySettings } from '../../../../providers/smb/smb.provider';

/**
 * Password policy interface (from ADDomain)
 */
interface PasswordPolicy {
  minPwdLength: number;
  pwdHistoryLength: number;
  lockoutThreshold: number;
  lockoutDuration: number;
  maxPwdAge: number;
  minPwdAge: number;
  complexityEnabled: boolean;
  reversibleEncryption: boolean;
}

// ==================== ANSSI COMPLIANCE DETECTORS ====================

/**
 * ANSSI R1 - Password Policy Compliance
 * Checks if password policy meets ANSSI recommendations:
 * - Minimum 12 characters for users, 16 for admins
 * - Password history >= 12
 * - Lockout threshold <= 5
 * - Maximum password age <= 90 days
 */
export function detectAnssiR1PasswordPolicy(
  domain: ADDomain,
  gpoSettings: GpoSecuritySettings | null,
  _includeDetails: boolean
): Finding {
  const issues: string[] = [];
  let compliant = true;

  // Check domain password policy
  const policy = domain['passwordPolicy'] as PasswordPolicy | undefined;
  if (policy) {
    if (policy.minPwdLength < 12) {
      issues.push(`Minimum password length ${policy.minPwdLength} < 12 required`);
      compliant = false;
    }
    if (policy.pwdHistoryLength < 12) {
      issues.push(`Password history ${policy.pwdHistoryLength} < 12 required`);
      compliant = false;
    }
    if (policy.lockoutThreshold > 5 && policy.lockoutThreshold !== 0) {
      issues.push(`Lockout threshold ${policy.lockoutThreshold} > 5 allowed`);
      compliant = false;
    }
    if (policy.maxPwdAge > 90) {
      issues.push(`Max password age ${policy.maxPwdAge} > 90 days`);
      compliant = false;
    }
  } else {
    issues.push('Password policy not configured or not readable');
    compliant = false;
  }

  // Check GPO settings for fine-grained password policy
  if (gpoSettings?.ldapServerIntegrity !== undefined) {
    // GPO settings available but no password policy in them
    // This is informational only
  }

  return {
    type: 'ANSSI_R1_PASSWORD_POLICY',
    severity: 'high',
    category: 'compliance',
    title: 'ANSSI R1 - Password Policy Non-Compliant',
    description:
      'Password policy does not meet ANSSI R1 recommendations. ANSSI requires minimum 12 characters, password history of 12, lockout threshold ≤5, and max age ≤90 days.',
    count: compliant ? 0 : 1,
    details: issues.length > 0 ? { violations: issues, framework: 'ANSSI', control: 'R1' } : undefined,
  };
}

/**
 * ANSSI R2 - Privileged Accounts Management
 * Checks privileged account compliance:
 * - Admin accounts should have separate user accounts
 * - Admin accounts should not have email
 * - Admin accounts should require smartcard
 * - Number of Domain Admins should be limited (<10)
 */
export function detectAnssiR2PrivilegedAccounts(
  users: ADUser[],
  _groups: ADGroup[],
  includeDetails: boolean
): Finding {
  const privilegedGroups = ['Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators'];
  const issues: { user: string; violations: string[] }[] = [];

  const privilegedUsers = users.filter((u) => {
    if (!u.memberOf) return false;
    return u.memberOf.some((dn) => privilegedGroups.some((pg) => dn.includes(`CN=${pg}`)));
  });

  // Check each privileged user
  for (const user of privilegedUsers) {
    const userIssues: string[] = [];

    // Admin account with email configured (should use separate account)
    if (user.mail) {
      userIssues.push('Admin account has email configured (use separate account)');
    }

    // Admin account without smartcard required
    const uac = user.userAccountControl || 0;
    if ((uac & 0x40000) === 0) {
      // SMARTCARD_REQUIRED flag not set
      userIssues.push('Smartcard not required for privileged account');
    }

    // Admin account enabled but never logged on
    if (user.enabled && !user.lastLogon) {
      userIssues.push('Enabled admin account never logged on');
    }

    if (userIssues.length > 0) {
      issues.push({ user: user.sAMAccountName, violations: userIssues });
    }
  }

  // Check total number of Domain Admins
  const domainAdmins = privilegedUsers.filter((u) =>
    u.memberOf?.some((dn) => dn.includes('CN=Domain Admins'))
  );
  const domainAdminCount = domainAdmins.length;

  return {
    type: 'ANSSI_R2_PRIVILEGED_ACCOUNTS',
    severity: 'high',
    category: 'compliance',
    title: 'ANSSI R2 - Privileged Accounts Non-Compliant',
    description:
      'Privileged accounts do not meet ANSSI R2 recommendations. Admin accounts should use separate identities, require smartcard, and not exceed 10 Domain Admins.',
    count: issues.length,
    affectedEntities: includeDetails
      ? toAffectedUserEntities(
          users.filter((u) => issues.some((i) => i.user === u.sAMAccountName))
        )
      : undefined,
    details:
      issues.length > 0
        ? {
            violations: issues.slice(0, 10),
            domainAdminCount,
            recommendation:
              domainAdminCount > 10
                ? `Reduce Domain Admins from ${domainAdminCount} to ≤10`
                : undefined,
            framework: 'ANSSI',
            control: 'R2',
          }
        : undefined,
  };
}

/**
 * ANSSI R3 - Strong Authentication
 * Checks if strong authentication is enforced:
 * - Kerberos AES encryption enabled
 * - NTLM restrictions in place
 * - Credential Guard considerations
 */
export function detectAnssiR3StrongAuth(
  users: ADUser[],
  domain: ADDomain,
  _includeDetails: boolean
): Finding {
  const issues: string[] = [];

  // Check domain functional level (impacts security features)
  const functionalLevel = (domain['domainFunctionalLevel'] as number) || 0;
  if (functionalLevel < 6) {
    // Windows Server 2012 R2
    issues.push(`Domain functional level ${functionalLevel} is below 2012 R2 (6), limiting security features`);
  }

  // Check users with weak encryption types
  const weakEncryptionUsers = users.filter((u) => {
    const encTypes = u['msDS-SupportedEncryptionTypes'] as number | undefined;
    if (typeof encTypes !== 'number') return false;
    // Only DES/RC4, no AES
    return (encTypes & 0x18) === 0 && (encTypes & 0x7) !== 0;
  });

  if (weakEncryptionUsers.length > 0) {
    issues.push(`${weakEncryptionUsers.length} users with weak encryption (no AES)`);
  }

  // Check for users without Kerberos pre-authentication
  const noPreAuthUsers = users.filter((u) => {
    const uac = u.userAccountControl || 0;
    return (uac & 0x400000) !== 0; // DONT_REQ_PREAUTH
  });

  if (noPreAuthUsers.length > 0) {
    issues.push(`${noPreAuthUsers.length} users without Kerberos pre-authentication`);
  }

  return {
    type: 'ANSSI_R3_STRONG_AUTH',
    severity: 'medium',
    category: 'compliance',
    title: 'ANSSI R3 - Strong Authentication Issues',
    description:
      'Strong authentication mechanisms not fully enforced per ANSSI R3. Kerberos AES should be required, and weak encryption types disabled.',
    count: issues.length > 0 ? 1 : 0,
    details: issues.length > 0 ? { violations: issues, framework: 'ANSSI', control: 'R3' } : undefined,
  };
}

/**
 * ANSSI R4 - Logging and Monitoring
 * Checks logging configuration compliance:
 * - Security event logging enabled
 * - Log size adequate
 * - Retention configured
 */
export function detectAnssiR4Logging(
  gpoSettings: GpoSecuritySettings | null,
  _includeDetails: boolean
): Finding {
  const issues: string[] = [];

  if (!gpoSettings) {
    issues.push('GPO settings not available for audit policy analysis');
  } else {
    // Check audit policy
    if (gpoSettings.auditPolicies && gpoSettings.auditPolicies.length > 0) {
      const audit = gpoSettings.auditPolicies;

      // Check essential audit categories
      const hasLogon = audit.some((p) => p.category.includes('Logon') && p.success && p.failure);
      const hasAccountMgmt = audit.some(
        (p) => p.category.includes('Account Management') && p.success && p.failure
      );
      const hasPolicyChange = audit.some(
        (p) => p.category.includes('Policy Change') && p.success && p.failure
      );
      const hasPrivilegeUse = audit.some(
        (p) => p.category.includes('Privilege Use') && p.success && p.failure
      );

      if (!hasLogon) issues.push('Logon events not fully audited');
      if (!hasAccountMgmt) issues.push('Account management not fully audited');
      if (!hasPolicyChange) issues.push('Policy changes not fully audited');
      if (!hasPrivilegeUse) issues.push('Privilege use not fully audited');
    } else {
      issues.push('Audit policy not configured');
    }
  }

  return {
    type: 'ANSSI_R4_LOGGING',
    severity: 'medium',
    category: 'compliance',
    title: 'ANSSI R4 - Logging Non-Compliant',
    description:
      'Logging configuration does not meet ANSSI R4 recommendations. All security events should be audited with adequate log retention.',
    count: issues.length > 0 ? 1 : 0,
    details: issues.length > 0 ? { violations: issues, framework: 'ANSSI', control: 'R4' } : undefined,
  };
}

/**
 * ANSSI R5 - Segregation
 * Checks network and privilege segregation:
 * - Tiered admin model
 * - Service account isolation
 * - Workstation restrictions
 */
export function detectAnssiR5Segregation(
  users: ADUser[],
  computers: ADComputer[],
  _includeDetails: boolean
): Finding {
  const issues: string[] = [];

  // Check for admin accounts logging into workstations (tier violation)
  const privilegedGroups = ['Domain Admins', 'Enterprise Admins', 'Schema Admins'];
  const admins = users.filter(
    (u) => u.memberOf?.some((dn) => privilegedGroups.some((pg) => dn.includes(`CN=${pg}`)))
  );

  // Check for service accounts with interactive logon capability
  const serviceAccounts = users.filter((u) => {
    const name = (u.sAMAccountName || '').toLowerCase();
    return name.includes('svc') || name.includes('service') || name.startsWith('sa_');
  });

  const interactiveServiceAccounts = serviceAccounts.filter((u) => {
    // Check if service account doesn't have "Deny logon locally" applied
    // This is a heuristic - real check would require GPO analysis
    return u.enabled;
  });

  if (interactiveServiceAccounts.length > 0) {
    issues.push(`${interactiveServiceAccounts.length} service accounts may allow interactive logon`);
  }

  // Check for workstations in server OUs (organizational issue)
  const workstationsInServerOu = computers.filter((c) => {
    const os = ldapAttrToString(c.operatingSystem);
    const isWorkstation = /windows 10|windows 11|windows 7|windows 8/i.test(os);
    const isInServerOu = /ou=servers|ou=server|ou=datacenter/i.test(c.dn);
    return isWorkstation && isInServerOu;
  });

  if (workstationsInServerOu.length > 0) {
    issues.push(`${workstationsInServerOu.length} workstations in server OUs (tier violation)`);
  }

  // Check admin count (too many admins indicates poor segregation)
  if (admins.length > 15) {
    issues.push(`${admins.length} privileged accounts (recommend <15 for proper segregation)`);
  }

  return {
    type: 'ANSSI_R5_SEGREGATION',
    severity: 'medium',
    category: 'compliance',
    title: 'ANSSI R5 - Segregation Issues',
    description:
      'Network and privilege segregation does not meet ANSSI R5 recommendations. Implement tiered administration model.',
    count: issues.length > 0 ? 1 : 0,
    details: issues.length > 0 ? { violations: issues, framework: 'ANSSI', control: 'R5' } : undefined,
  };
}

// ==================== NIST COMPLIANCE DETECTORS ====================

/**
 * NIST AC-2 - Account Management
 * Checks account management compliance:
 * - Inactive accounts disabled
 * - Guest account disabled
 * - Service accounts documented
 */
export function detectNistAc2AccountManagement(
  users: ADUser[],
  includeDetails: boolean
): Finding {
  const issues: { issue: string; count: number }[] = [];
  const affectedUsers: ADUser[] = [];

  // Check for inactive accounts (90 days)
  const now = Date.now();
  const ninetyDaysAgo = now - 90 * 24 * 60 * 60 * 1000;
  const inactiveAccounts = users.filter(
    (u) => u.enabled && u.lastLogon && u.lastLogon.getTime() < ninetyDaysAgo
  );
  if (inactiveAccounts.length > 0) {
    issues.push({ issue: 'Inactive accounts (90+ days) still enabled', count: inactiveAccounts.length });
    affectedUsers.push(...inactiveAccounts);
  }

  // Check for enabled accounts that have never logged on
  const neverLoggedOn = users.filter((u) => u.enabled && !u.lastLogon);
  if (neverLoggedOn.length > 0) {
    issues.push({ issue: 'Enabled accounts never logged on', count: neverLoggedOn.length });
    affectedUsers.push(...neverLoggedOn.filter((u) => !affectedUsers.includes(u)));
  }

  // Check for Guest account enabled
  const guestEnabled = users.filter(
    (u) => u.sAMAccountName.toLowerCase() === 'guest' && u.enabled
  );
  if (guestEnabled.length > 0) {
    issues.push({ issue: 'Guest account enabled', count: 1 });
    affectedUsers.push(...guestEnabled);
  }

  return {
    type: 'NIST_AC_2_ACCOUNT_MANAGEMENT',
    severity: 'high',
    category: 'compliance',
    title: 'NIST AC-2 - Account Management Issues',
    description:
      'Account management does not comply with NIST AC-2. Inactive accounts should be disabled, guest account should be disabled.',
    count: affectedUsers.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affectedUsers.slice(0, 50)) : undefined,
    details: issues.length > 0 ? { violations: issues, framework: 'NIST', control: 'AC-2' } : undefined,
  };
}

/**
 * NIST AC-6 - Least Privilege
 * Checks least privilege compliance:
 * - Users with unnecessary admin rights
 * - Excessive group memberships
 * - Accounts with elevated privileges
 */
export function detectNistAc6LeastPrivilege(
  users: ADUser[],
  groups: ADGroup[],
  includeDetails: boolean
): Finding {
  const issues: { issue: string; count: number }[] = [];
  const affectedUsers: ADUser[] = [];

  const sensitiveGroups = [
    'Domain Admins',
    'Enterprise Admins',
    'Schema Admins',
    'Administrators',
    'Account Operators',
    'Backup Operators',
    'Server Operators',
    'Print Operators',
  ];

  // Check users in multiple sensitive groups
  const usersInMultipleSensitiveGroups = users.filter((u) => {
    if (!u.memberOf) return false;
    const sensitiveCount = u.memberOf.filter((dn) =>
      sensitiveGroups.some((sg) => dn.includes(`CN=${sg}`))
    ).length;
    return sensitiveCount > 1;
  });

  if (usersInMultipleSensitiveGroups.length > 0) {
    issues.push({
      issue: 'Users in multiple sensitive groups',
      count: usersInMultipleSensitiveGroups.length,
    });
    affectedUsers.push(...usersInMultipleSensitiveGroups);
  }

  // Check for excessive Domain Admins (>5)
  const domainAdmins = users.filter(
    (u) => u.memberOf?.some((dn) => dn.includes('CN=Domain Admins'))
  );
  if (domainAdmins.length > 5) {
    issues.push({
      issue: `Excessive Domain Admins (${domainAdmins.length}, recommend ≤5)`,
      count: domainAdmins.length,
    });
  }

  // Check for groups with excessive members (privilege creep indicator)
  const oversizedPrivilegedGroups = groups.filter((g) => {
    const isSensitive = sensitiveGroups.some(
      (sg) => g.sAMAccountName?.toLowerCase() === sg.toLowerCase()
    );
    return isSensitive && (g.member?.length || 0) > 10;
  });

  if (oversizedPrivilegedGroups.length > 0) {
    issues.push({
      issue: 'Privileged groups with >10 members',
      count: oversizedPrivilegedGroups.length,
    });
  }

  return {
    type: 'NIST_AC_6_LEAST_PRIVILEGE',
    severity: 'high',
    category: 'compliance',
    title: 'NIST AC-6 - Least Privilege Violations',
    description:
      'Privilege assignments do not comply with NIST AC-6 least privilege principle. Review and reduce excessive privileges.',
    count: affectedUsers.length + oversizedPrivilegedGroups.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affectedUsers.slice(0, 50)) : undefined,
    details: issues.length > 0 ? { violations: issues, framework: 'NIST', control: 'AC-6' } : undefined,
  };
}

/**
 * NIST IA-5 - Authenticator Management
 * Checks authenticator compliance:
 * - Password complexity
 * - Account lockout
 * - Password age
 */
export function detectNistIa5Authenticator(
  domain: ADDomain,
  users: ADUser[],
  _includeDetails: boolean
): Finding {
  const issues: string[] = [];

  // Check password policy
  const policy = domain['passwordPolicy'] as PasswordPolicy | undefined;
  if (policy) {
    if (!policy.complexityEnabled) {
      issues.push('Password complexity not enabled');
    }
    if (policy.minPwdLength < 14) {
      issues.push(`Minimum password length ${policy.minPwdLength} < 14 (NIST recommends 14+)`);
    }
    if (policy.lockoutThreshold === 0) {
      issues.push('Account lockout not configured');
    }
  }

  // Check for accounts with password not required
  const noPasswordRequired = users.filter((u) => {
    const uac = u.userAccountControl || 0;
    return (uac & 0x20) !== 0; // PASSWD_NOTREQD
  });

  if (noPasswordRequired.length > 0) {
    issues.push(`${noPasswordRequired.length} accounts with password not required`);
  }

  // Check for reversible encryption
  const reversibleEncryption = users.filter((u) => {
    const uac = u.userAccountControl || 0;
    return (uac & 0x80) !== 0; // ENCRYPTED_TEXT_PWD_ALLOWED
  });

  if (reversibleEncryption.length > 0) {
    issues.push(`${reversibleEncryption.length} accounts with reversible encryption`);
  }

  return {
    type: 'NIST_IA_5_AUTHENTICATOR',
    severity: 'medium',
    category: 'compliance',
    title: 'NIST IA-5 - Authenticator Management Issues',
    description:
      'Authenticator management does not comply with NIST IA-5. Password policies should enforce complexity and secure storage.',
    count: issues.length > 0 ? 1 : 0,
    details: issues.length > 0 ? { violations: issues, framework: 'NIST', control: 'IA-5' } : undefined,
  };
}

/**
 * NIST AU-2 - Audit Events
 * Checks audit event configuration:
 * - Essential events audited
 * - Audit policy completeness
 */
export function detectNistAu2AuditEvents(
  gpoSettings: GpoSecuritySettings | null,
  _includeDetails: boolean
): Finding {
  const issues: string[] = [];

  if (!gpoSettings?.auditPolicies || gpoSettings.auditPolicies.length === 0) {
    issues.push('Audit policy not configured or not readable');
  } else {
    const audit = gpoSettings.auditPolicies;

    // NIST AU-2 required events
    const requiredCategories = [
      'Account Logon',
      'Account Management',
      'Policy Change',
      'System',
      'Object Access',
    ];

    for (const category of requiredCategories) {
      const hasCategory = audit.some(
        (p) => p.category.includes(category) && p.success && p.failure
      );
      if (!hasCategory) {
        issues.push(`${category} not fully audited (success and failure)`);
      }
    }
  }

  return {
    type: 'NIST_AU_2_AUDIT_EVENTS',
    severity: 'medium',
    category: 'compliance',
    title: 'NIST AU-2 - Audit Events Non-Compliant',
    description:
      'Audit event configuration does not comply with NIST AU-2. All security-relevant events should be audited.',
    count: issues.length > 0 ? 1 : 0,
    details: issues.length > 0 ? { violations: issues, framework: 'NIST', control: 'AU-2' } : undefined,
  };
}

// ==================== CIS COMPLIANCE DETECTORS ====================

/**
 * CIS Password Policy (2.3.1.x)
 * Checks CIS Benchmark password policy recommendations
 */
export function detectCisPasswordPolicy(
  domain: ADDomain,
  _includeDetails: boolean
): Finding {
  const issues: string[] = [];

  const policy = domain['passwordPolicy'] as PasswordPolicy | undefined;
  if (policy) {
    // CIS recommends minimum 14 characters
    if (policy.minPwdLength < 14) {
      issues.push(`Minimum password length ${policy.minPwdLength} < 14 (CIS 1.1.1)`);
    }
    // CIS recommends password history of 24
    if (policy.pwdHistoryLength < 24) {
      issues.push(`Password history ${policy.pwdHistoryLength} < 24 (CIS 1.1.2)`);
    }
    // CIS recommends max password age 365 days or less
    if (policy.maxPwdAge > 365) {
      issues.push(`Max password age ${policy.maxPwdAge} > 365 days (CIS 1.1.3)`);
    }
    // CIS recommends minimum password age of 1 day
    if (policy.minPwdAge < 1) {
      issues.push(`Min password age ${policy.minPwdAge} < 1 day (CIS 1.1.4)`);
    }
    // Complexity should be enabled
    if (!policy.complexityEnabled) {
      issues.push('Password complexity not enabled (CIS 1.1.5)');
    }
    // Reversible encryption should be disabled
    if (policy.reversibleEncryption) {
      issues.push('Reversible encryption enabled (CIS 1.1.6)');
    }
  } else {
    issues.push('Password policy not available');
  }

  return {
    type: 'CIS_PASSWORD_POLICY',
    severity: 'high',
    category: 'compliance',
    title: 'CIS Benchmark - Password Policy Non-Compliant',
    description:
      'Password policy does not meet CIS Benchmark recommendations. Review and update password policy settings.',
    count: issues.length > 0 ? 1 : 0,
    details: issues.length > 0 ? { violations: issues, framework: 'CIS', control: '1.1.x' } : undefined,
  };
}

/**
 * CIS Network Security (2.3.7.x)
 * Checks CIS Benchmark network security settings
 */
export function detectCisNetworkSecurity(
  gpoSettings: GpoSecuritySettings | null,
  _includeDetails: boolean
): Finding {
  const issues: string[] = [];

  if (gpoSettings) {
    // Check SMBv1
    if (gpoSettings.smbv1ServerEnabled || gpoSettings.smbv1ClientEnabled) {
      issues.push('SMBv1 enabled (CIS 2.3.7.1 - Disable SMBv1)');
    }

    // Check LDAP signing
    if (gpoSettings.ldapServerIntegrity !== undefined && gpoSettings.ldapServerIntegrity < 2) {
      issues.push('LDAP signing not required (CIS 2.3.7.2)');
    }

    // Check LDAP channel binding
    if (gpoSettings.ldapChannelBinding !== undefined && gpoSettings.ldapChannelBinding < 2) {
      issues.push('LDAP channel binding not required (CIS 2.3.7.3)');
    }
  } else {
    issues.push('GPO settings not available for network security analysis');
  }

  return {
    type: 'CIS_NETWORK_SECURITY',
    severity: 'medium',
    category: 'compliance',
    title: 'CIS Benchmark - Network Security Non-Compliant',
    description:
      'Network security settings do not meet CIS Benchmark recommendations. SMBv1 should be disabled, LDAP signing required.',
    count: issues.length > 0 ? 1 : 0,
    details: issues.length > 0 ? { violations: issues, framework: 'CIS', control: '2.3.7.x' } : undefined,
  };
}

/**
 * CIS User Rights (2.3.11.x)
 * Checks CIS Benchmark user rights assignments
 */
export function detectCisUserRights(
  users: ADUser[],
  groups: ADGroup[],
  _includeDetails: boolean
): Finding {
  const issues: string[] = [];

  // Check for Everyone or Authenticated Users in privileged groups
  const sensitiveGroups = ['Administrators', 'Domain Admins', 'Enterprise Admins'];
  const problematicMembers = ['Everyone', 'Authenticated Users', 'ANONYMOUS LOGON'];

  for (const group of groups) {
    const isSensitive = sensitiveGroups.some(
      (sg) => group.sAMAccountName?.toLowerCase() === sg.toLowerCase()
    );
    if (!isSensitive) continue;

    const hasProblematicMember = group.member?.some((memberDn) =>
      problematicMembers.some((pm) => memberDn.toLowerCase().includes(pm.toLowerCase()))
    );

    if (hasProblematicMember) {
      issues.push(`${group.sAMAccountName} contains well-known security principal (CIS 2.3.11.x)`);
    }
  }

  // Check for accounts with "Act as part of the operating system" potential
  const trustedForDelegation = users.filter((u) => {
    const uac = u.userAccountControl || 0;
    return (uac & 0x80000) !== 0; // TRUSTED_FOR_DELEGATION
  });

  if (trustedForDelegation.length > 0) {
    issues.push(`${trustedForDelegation.length} users trusted for delegation (CIS 2.3.11.x)`);
  }

  return {
    type: 'CIS_USER_RIGHTS',
    severity: 'medium',
    category: 'compliance',
    title: 'CIS Benchmark - User Rights Issues',
    description:
      'User rights assignments do not meet CIS Benchmark recommendations. Review delegation and group memberships.',
    count: issues.length > 0 ? 1 : 0,
    details: issues.length > 0 ? { violations: issues, framework: 'CIS', control: '2.3.11.x' } : undefined,
  };
}

// ==================== DISA STIG COMPLIANCE DETECTORS ====================

/**
 * DISA STIG V-220857 - Account Policies
 * Checks DISA STIG account policy requirements
 */
export function detectDisaAccountPolicies(
  domain: ADDomain,
  users: ADUser[],
  _includeDetails: boolean
): Finding {
  const issues: string[] = [];

  const policy = domain['passwordPolicy'] as PasswordPolicy | undefined;
  if (policy) {
    // DISA requires minimum 15 characters for privileged accounts
    if (policy.minPwdLength < 15) {
      issues.push(`Min password length ${policy.minPwdLength} < 15 (V-220857)`);
    }
    // Lockout duration must be 0 (until admin unlock) or >= 15 minutes
    if (policy.lockoutDuration > 0 && policy.lockoutDuration < 15) {
      issues.push(`Lockout duration ${policy.lockoutDuration} min < 15 min (V-220857)`);
    }
    // Lockout threshold must be <= 3
    if (policy.lockoutThreshold > 3) {
      issues.push(`Lockout threshold ${policy.lockoutThreshold} > 3 (V-220857)`);
    }
  }

  // Check for accounts without password expiration (except service accounts)
  const noExpiration = users.filter((u) => {
    const uac = u.userAccountControl || 0;
    const hasNoExpire = (uac & 0x10000) !== 0; // DONT_EXPIRE_PASSWORD
    const isServiceAccount =
      u.sAMAccountName.toLowerCase().includes('svc') ||
      u.sAMAccountName.toLowerCase().includes('service');
    return hasNoExpire && !isServiceAccount;
  });

  if (noExpiration.length > 0) {
    issues.push(`${noExpiration.length} non-service accounts with password never expires (V-220857)`);
  }

  return {
    type: 'DISA_ACCOUNT_POLICIES',
    severity: 'high',
    category: 'compliance',
    title: 'DISA STIG - Account Policies Non-Compliant',
    description:
      'Account policies do not comply with DISA STIG V-220857. Review password and lockout policy settings.',
    count: issues.length > 0 ? 1 : 0,
    details: issues.length > 0 ? { violations: issues, framework: 'DISA', control: 'V-220857' } : undefined,
  };
}

/**
 * DISA STIG V-220858 - Audit Policies
 * Checks DISA STIG audit policy requirements
 */
export function detectDisaAuditPolicies(
  gpoSettings: GpoSecuritySettings | null,
  _includeDetails: boolean
): Finding {
  const issues: string[] = [];

  if (!gpoSettings?.auditPolicies || gpoSettings.auditPolicies.length === 0) {
    issues.push('Audit policy not configured (V-220858)');
  } else {
    const audit = gpoSettings.auditPolicies;

    // DISA requires specific audit categories
    const disaRequirements = [
      { name: 'Account Logon (Success)', check: (a: typeof audit) => a.some((p) => p.category.includes('Logon') && p.success) },
      { name: 'Account Logon (Failure)', check: (a: typeof audit) => a.some((p) => p.category.includes('Logon') && p.failure) },
      { name: 'Account Management (Success)', check: (a: typeof audit) => a.some((p) => p.category.includes('Account Management') && p.success) },
      { name: 'Account Management (Failure)', check: (a: typeof audit) => a.some((p) => p.category.includes('Account Management') && p.failure) },
      { name: 'Policy Change (Success)', check: (a: typeof audit) => a.some((p) => p.category.includes('Policy Change') && p.success) },
      { name: 'Policy Change (Failure)', check: (a: typeof audit) => a.some((p) => p.category.includes('Policy Change') && p.failure) },
      { name: 'Privilege Use (Success)', check: (a: typeof audit) => a.some((p) => p.category.includes('Privilege Use') && p.success) },
      { name: 'Privilege Use (Failure)', check: (a: typeof audit) => a.some((p) => p.category.includes('Privilege Use') && p.failure) },
    ];

    for (const req of disaRequirements) {
      if (!req.check(audit)) {
        issues.push(`${req.name} audit not enabled (V-220858)`);
      }
    }
  }

  return {
    type: 'DISA_AUDIT_POLICIES',
    severity: 'high',
    category: 'compliance',
    title: 'DISA STIG - Audit Policies Non-Compliant',
    description:
      'Audit policies do not comply with DISA STIG V-220858. All required audit categories should be enabled.',
    count: issues.length > 0 ? 1 : 0,
    details: issues.length > 0 ? { violations: issues, framework: 'DISA', control: 'V-220858' } : undefined,
  };
}

// ==================== INDUSTRY FRAMEWORKS (PCI-DSS, SOC2, GDPR, SOX, DORA, HIPAA, ISO27001) ====================

/**
 * MFA_NOT_ENFORCED - Privileged accounts without MFA
 * Frameworks: PCI-DSS 8.3, SOC2 CC6.1, ISO27001 A.9.4.2
 * Checks if privileged accounts require smartcard/MFA
 */
export function detectMfaNotEnforced(
  users: ADUser[],
  includeDetails: boolean
): Finding {
  const privilegedGroups = ['Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators'];

  const privilegedUsers = users.filter((u) => {
    if (!u.memberOf) return false;
    return u.memberOf.some((dn) => privilegedGroups.some((pg) => dn.includes(`CN=${pg}`)));
  });

  // Check for privileged users without SMARTCARD_REQUIRED flag
  const noMfa = privilegedUsers.filter((u) => {
    const uac = u.userAccountControl || 0;
    return (uac & 0x40000) === 0; // SMARTCARD_REQUIRED not set
  });

  return {
    type: 'MFA_NOT_ENFORCED',
    severity: 'high',
    category: 'compliance',
    title: 'MFA Not Enforced for Privileged Accounts',
    description:
      'Privileged accounts do not require multi-factor authentication (smartcard). Required by PCI-DSS 8.3, SOC2 CC6.1, ISO27001 A.9.4.2.',
    count: noMfa.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(noMfa.slice(0, 50)) : undefined,
    details: noMfa.length > 0 ? {
      frameworks: ['PCI-DSS', 'SOC2', 'ISO27001'],
      controls: ['8.3', 'CC6.1', 'A.9.4.2'],
      recommendation: 'Enable smartcard requirement for all privileged accounts',
    } : undefined,
  };
}

/**
 * BACKUP_AD_NOT_VERIFIED - No recent AD backup
 * Frameworks: SOC2 A1.2, DORA Art.11, ISO27001 A.12.3.1
 * Checks if AD has recent backup (based on tombstone lifetime and domain metadata)
 */
export function detectBackupNotVerified(
  domain: ADDomain,
  _includeDetails: boolean
): Finding {
  const issues: string[] = [];

  // Check tombstone lifetime (default 180 days, should be configured)
  const tombstoneLifetime = (domain['tombstoneLifetime'] as number) || 180;

  // If tombstone is default, backup policy may not be reviewed
  if (tombstoneLifetime === 180 || tombstoneLifetime === 60) {
    issues.push(`Tombstone lifetime is default (${tombstoneLifetime} days) - backup policy may not be configured`);
  }

  // Check for backup indicators in domain (this is heuristic)
  // Real backup verification requires checking Windows Server Backup or third-party tools
  const lastBackup = domain['lastBackupTime'] as Date | undefined;
  if (!lastBackup) {
    issues.push('No backup metadata found - verify AD backup is configured and tested');
  }

  return {
    type: 'BACKUP_AD_NOT_VERIFIED',
    severity: 'high',
    category: 'compliance',
    title: 'AD Backup Not Verified',
    description:
      'Active Directory backup configuration cannot be verified. Required by SOC2 A1.2, DORA Article 11, ISO27001 A.12.3.1.',
    count: issues.length > 0 ? 1 : 0,
    details: issues.length > 0 ? {
      violations: issues,
      frameworks: ['SOC2', 'DORA', 'ISO27001'],
      controls: ['A1.2', 'Art.11', 'A.12.3.1'],
      recommendation: 'Configure and regularly test AD system state backups',
    } : undefined,
  };
}

/**
 * AUDIT_LOG_RETENTION_SHORT - Log retention below requirements
 * Frameworks: SOX Section 802, HIPAA 164.312(b), PCI-DSS 10.7
 * Checks if audit log retention meets compliance requirements (1 year minimum)
 */
export function detectAuditLogRetentionShort(
  gpoSettings: GpoSecuritySettings | null,
  _includeDetails: boolean
): Finding {
  const issues: string[] = [];

  // Check if audit policy is configured (indicates logging is set up)
  if (!gpoSettings?.auditPolicies || gpoSettings.auditPolicies.length === 0) {
    issues.push('Audit policy not configured - log retention cannot be verified');
  } else {
    // Check if essential events are being audited (prerequisite for retention)
    const hasSecurityAudit = gpoSettings.auditPolicies.some(
      (p) => p.category.includes('Logon') || p.category.includes('Account')
    );
    if (!hasSecurityAudit) {
      issues.push('Security events not being audited - retention policy meaningless without logging');
    }
  }

  // Note: Actual log retention settings are in Windows Event Log configuration
  // which requires additional GPO parsing or WMI queries not currently available
  // This check ensures audit infrastructure exists as prerequisite
  if (issues.length === 0) {
    issues.push('Log retention period should be verified manually (1 year minimum for compliance)');
  }

  return {
    type: 'AUDIT_LOG_RETENTION_SHORT',
    severity: 'high',
    category: 'compliance',
    title: 'Audit Log Retention Below Requirements',
    description:
      'Audit log retention period may not meet compliance requirements (1 year minimum). Required by SOX Section 802, HIPAA 164.312(b), PCI-DSS 10.7.',
    count: issues.length > 0 ? 1 : 0,
    details: issues.length > 0 ? {
      violations: issues,
      frameworks: ['SOX', 'HIPAA', 'PCI-DSS'],
      controls: ['Section 802', '164.312(b)', '10.7'],
      recommendation: 'Configure log retention for minimum 1 year with SIEM integration',
    } : undefined,
  };
}

/**
 * PRIVILEGED_ACCESS_REVIEW_MISSING - No recent access review
 * Frameworks: SOX Section 404, ISO27001 A.9.2.5, SOC2 CC6.2
 * Checks if privileged group membership has been reviewed recently
 */
export function detectPrivilegedAccessReviewMissing(
  users: ADUser[],
  groups: ADGroup[],
  _includeDetails: boolean
): Finding {
  const issues: string[] = [];
  const NINETY_DAYS_MS = 90 * 24 * 60 * 60 * 1000;
  const now = Date.now();

  const privilegedGroupNames = ['Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators'];

  // Check privileged groups for stale membership
  for (const group of groups) {
    if (!privilegedGroupNames.some(pg => group.sAMAccountName?.toLowerCase() === pg.toLowerCase())) {
      continue;
    }

    // Check whenChanged on group (indicates membership review)
    const groupChanged = group['whenChanged'] as Date | undefined;
    if (groupChanged && (now - groupChanged.getTime()) > NINETY_DAYS_MS) {
      // Group not modified in 90 days - may indicate no access review
      const memberCount = group.member?.length || 0;
      if (memberCount > 0) {
        issues.push(`${group.sAMAccountName} (${memberCount} members) not reviewed in 90+ days`);
      }
    }
  }

  // Check for admin accounts with very old last logon (may be orphaned)
  const privilegedUsers = users.filter((u) => {
    if (!u.memberOf) return false;
    return u.memberOf.some((dn) => privilegedGroupNames.some((pg) => dn.includes(`CN=${pg}`)));
  });

  const staleAdmins = privilegedUsers.filter((u) => {
    if (!u.lastLogon) return true; // Never logged on
    return (now - u.lastLogon.getTime()) > NINETY_DAYS_MS;
  });

  if (staleAdmins.length > 0) {
    issues.push(`${staleAdmins.length} privileged accounts inactive for 90+ days`);
  }

  return {
    type: 'PRIVILEGED_ACCESS_REVIEW_MISSING',
    severity: 'medium',
    category: 'compliance',
    title: 'Privileged Access Review Missing',
    description:
      'Privileged access has not been reviewed recently. Required by SOX Section 404, ISO27001 A.9.2.5, SOC2 CC6.2.',
    count: issues.length > 0 ? 1 : 0,
    details: issues.length > 0 ? {
      violations: issues,
      frameworks: ['SOX', 'ISO27001', 'SOC2'],
      controls: ['Section 404', 'A.9.2.5', 'CC6.2'],
      recommendation: 'Implement quarterly privileged access reviews with documented approval',
    } : undefined,
  };
}

/**
 * DATA_CLASSIFICATION_MISSING - OUs without data classification
 * Frameworks: GDPR Art.30, ISO27001 A.8.2.1, HIPAA 164.312
 * Checks if organizational structure supports data classification
 */
export function detectDataClassificationMissing(
  domain: ADDomain,
  _includeDetails: boolean
): Finding {
  const issues: string[] = [];

  // Check domain description for classification policy
  const domainDescription = (domain['description'] as string) || '';
  const hasClassificationKeywords = /confidential|restricted|internal|public|sensitive|pii|phi|pci/i.test(domainDescription);

  if (!hasClassificationKeywords) {
    issues.push('Domain description does not indicate data classification policy');
  }

  // Check for classification-related attributes in schema (heuristic)
  // Real check would involve examining OU descriptions and custom attributes
  const msExchVersion = domain['msExchVersion'] as number | undefined;
  if (msExchVersion) {
    // Exchange present - likely has email data requiring classification
    issues.push('Exchange detected - email data classification policy required for GDPR/HIPAA');
  }

  return {
    type: 'DATA_CLASSIFICATION_MISSING',
    severity: 'medium',
    category: 'compliance',
    title: 'Data Classification Not Implemented',
    description:
      'Data classification scheme not detected in AD structure. Required by GDPR Article 30, ISO27001 A.8.2.1, HIPAA 164.312.',
    count: issues.length > 0 ? 1 : 0,
    details: issues.length > 0 ? {
      violations: issues,
      frameworks: ['GDPR', 'ISO27001', 'HIPAA'],
      controls: ['Art.30', 'A.8.2.1', '164.312'],
      recommendation: 'Implement data classification scheme using OU structure and object attributes',
    } : undefined,
  };
}

/**
 * CHANGE_MANAGEMENT_BYPASS - Changes outside approved process
 * Frameworks: SOX Section 404, ISO27001 A.12.1.2, SOC2 CC8.1
 * Detects admin changes that may bypass change management
 */
export function detectChangeManagementBypass(
  users: ADUser[],
  groups: ADGroup[],
  _includeDetails: boolean
): Finding {
  const issues: string[] = [];
  const SEVEN_DAYS_MS = 7 * 24 * 60 * 60 * 1000;
  const now = Date.now();

  const privilegedGroupNames = ['Domain Admins', 'Enterprise Admins', 'Schema Admins'];

  // Check for recent privileged group changes (potential bypass indicators)
  for (const group of groups) {
    if (!privilegedGroupNames.some(pg => group.sAMAccountName?.toLowerCase() === pg.toLowerCase())) {
      continue;
    }

    const groupChanged = group['whenChanged'] as Date | undefined;
    if (groupChanged && (now - groupChanged.getTime()) < SEVEN_DAYS_MS) {
      issues.push(`${group.sAMAccountName} modified in last 7 days - verify change request exists`);
    }
  }

  // Check for recently created admin accounts
  const recentAdmins = users.filter((u) => {
    if (!u.memberOf?.some((dn) => privilegedGroupNames.some((pg) => dn.includes(`CN=${pg}`)))) {
      return false;
    }
    const created = u['whenCreated'] as Date | undefined;
    return created && (now - created.getTime()) < SEVEN_DAYS_MS;
  });

  if (recentAdmins.length > 0) {
    issues.push(`${recentAdmins.length} privileged accounts created in last 7 days - verify change requests`);
  }

  return {
    type: 'CHANGE_MANAGEMENT_BYPASS',
    severity: 'high',
    category: 'compliance',
    title: 'Potential Change Management Bypass',
    description:
      'Recent privileged changes detected - verify change management process was followed. Required by SOX Section 404, ISO27001 A.12.1.2, SOC2 CC8.1.',
    count: issues.length > 0 ? 1 : 0,
    details: issues.length > 0 ? {
      violations: issues,
      frameworks: ['SOX', 'ISO27001', 'SOC2'],
      controls: ['Section 404', 'A.12.1.2', 'CC8.1'],
      recommendation: 'Implement privileged change approval workflow with audit trail',
    } : undefined,
  };
}

/**
 * VENDOR_ACCOUNT_UNMONITORED - Third-party accounts not monitored
 * Frameworks: DORA Art.28, ISO27001 A.15.1.1, SOC2 CC9.2
 * Detects vendor/external accounts that may lack monitoring
 */
export function detectVendorAccountUnmonitored(
  users: ADUser[],
  includeDetails: boolean
): Finding {
  // Patterns that indicate vendor/external accounts
  const vendorPatterns = [
    /vendor/i, /external/i, /contractor/i, /consultant/i,
    /partner/i, /third.?party/i, /supplier/i, /^ext[_-]/i,
    /^v[_-]/i, /^tmp[_-]/i, /^temp[_-]/i
  ];

  const vendorAccounts = users.filter((u) => {
    const name = u.sAMAccountName || '';
    const desc = (u['description'] as string) || '';
    const displayName = u.displayName || '';

    return vendorPatterns.some(p =>
      p.test(name) || p.test(desc) || p.test(displayName)
    );
  });

  // Check which vendor accounts lack monitoring indicators
  const unmonitoredVendors = vendorAccounts.filter((u) => {
    // Check for account expiration (vendors should have expiry)
    const accountExpires = u['accountExpires'] as Date | bigint | number | undefined;
    let hasExpiry = false;
    if (accountExpires) {
      if (typeof accountExpires === 'bigint') {
        // Never expires: 9223372036854775807 or 0
        hasExpiry = accountExpires !== BigInt('9223372036854775807') && accountExpires !== BigInt(0);
      } else if (typeof accountExpires === 'number') {
        hasExpiry = accountExpires !== 9223372036854775807 && accountExpires !== 0;
      } else if (accountExpires instanceof Date) {
        hasExpiry = accountExpires.getTime() > Date.now();
      }
    }

    // Check for recent activity
    const lastLogon = u.lastLogon;
    const NINETY_DAYS_MS = 90 * 24 * 60 * 60 * 1000;
    const isActive = lastLogon && (Date.now() - lastLogon.getTime()) < NINETY_DAYS_MS;

    // Flag if no expiry AND active (should be monitored)
    return !hasExpiry && isActive;
  });

  return {
    type: 'VENDOR_ACCOUNT_UNMONITORED',
    severity: 'medium',
    category: 'compliance',
    title: 'Vendor Accounts Not Properly Monitored',
    description:
      'Third-party/vendor accounts detected without proper expiration or monitoring controls. Required by DORA Article 28, ISO27001 A.15.1.1, SOC2 CC9.2.',
    count: unmonitoredVendors.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(unmonitoredVendors.slice(0, 50)) : undefined,
    details: unmonitoredVendors.length > 0 ? {
      totalVendorAccounts: vendorAccounts.length,
      unmonitoredCount: unmonitoredVendors.length,
      frameworks: ['DORA', 'ISO27001', 'SOC2'],
      controls: ['Art.28', 'A.15.1.1', 'CC9.2'],
      recommendation: 'Set expiration dates and enable enhanced logging for all vendor accounts',
    } : undefined,
  };
}

/**
 * ENCRYPTION_AT_REST_DISABLED - BitLocker not deployed on DCs
 * Frameworks: PCI-DSS 3.4, HIPAA 164.312(a)(2)(iv), ISO27001 A.10.1.1
 * Checks if domain controllers have encryption indicators
 */
export function detectEncryptionAtRestDisabled(
  computers: ADComputer[],
  _includeDetails: boolean
): Finding {
  // Find domain controllers
  const domainControllers = computers.filter((c) => {
    const uac = c.userAccountControl || 0;
    return (uac & 0x2000) !== 0; // SERVER_TRUST_ACCOUNT
  });

  // Check for BitLocker recovery information
  // In AD, BitLocker keys are stored as msFVE-RecoveryInformation objects linked to computer
  const dcsWithoutBitLocker = domainControllers.filter((dc) => {
    // Check for msFVE attributes (BitLocker)
    const hasBitLocker = dc['msFVE-RecoveryPassword'] || dc['msFVE-KeyPackage'];
    return !hasBitLocker;
  });

  // Also check all servers for encryption
  const servers = computers.filter((c) => {
    const os = ldapAttrToString(c.operatingSystem).toLowerCase();
    return os.includes('server') && !domainControllers.includes(c);
  });

  const serversWithoutBitLocker = servers.filter((s) => {
    const hasBitLocker = s['msFVE-RecoveryPassword'] || s['msFVE-KeyPackage'];
    return !hasBitLocker;
  });

  const issues: string[] = [];
  if (dcsWithoutBitLocker.length > 0) {
    issues.push(`${dcsWithoutBitLocker.length}/${domainControllers.length} Domain Controllers without BitLocker`);
  }
  if (serversWithoutBitLocker.length > 0 && serversWithoutBitLocker.length === servers.length) {
    issues.push(`No servers have BitLocker recovery stored in AD`);
  }

  return {
    type: 'ENCRYPTION_AT_REST_DISABLED',
    severity: 'high',
    category: 'compliance',
    title: 'Encryption at Rest Not Deployed',
    description:
      'BitLocker encryption not detected on domain controllers or servers. Required by PCI-DSS 3.4, HIPAA 164.312(a)(2)(iv), ISO27001 A.10.1.1.',
    count: dcsWithoutBitLocker.length,
    details: issues.length > 0 ? {
      violations: issues,
      domainControllers: domainControllers.length,
      dcsWithBitLocker: domainControllers.length - dcsWithoutBitLocker.length,
      frameworks: ['PCI-DSS', 'HIPAA', 'ISO27001'],
      controls: ['3.4', '164.312(a)(2)(iv)', 'A.10.1.1'],
      recommendation: 'Deploy BitLocker on all domain controllers and servers with AD key backup',
    } : undefined,
  };
}

// ==================== COMPLIANCE SCORE ====================

/**
 * Framework tracking interface
 */
interface FrameworkScore {
  total: number;
  passed: number;
}

/**
 * Calculate overall compliance score
 * Provides a summary of compliance across all frameworks
 */
export function detectComplianceScore(
  findings: Finding[],
  _includeDetails: boolean
): Finding {
  // Count compliance findings by framework
  const anssi: FrameworkScore = { total: 5, passed: 0 };
  const nist: FrameworkScore = { total: 4, passed: 0 };
  const cis: FrameworkScore = { total: 3, passed: 0 };
  const disa: FrameworkScore = { total: 2, passed: 0 };
  const industry: FrameworkScore = { total: 8, passed: 0 }; // PCI-DSS, SOC2, GDPR, SOX, DORA, HIPAA, ISO27001

  // Industry framework detection types
  const industryTypes = [
    'MFA_NOT_ENFORCED',
    'BACKUP_AD_NOT_VERIFIED',
    'AUDIT_LOG_RETENTION_SHORT',
    'PRIVILEGED_ACCESS_REVIEW_MISSING',
    'DATA_CLASSIFICATION_MISSING',
    'CHANGE_MANAGEMENT_BYPASS',
    'VENDOR_ACCOUNT_UNMONITORED',
    'ENCRYPTION_AT_REST_DISABLED',
  ];

  // Check each compliance finding
  const complianceFindings = findings.filter((f) => f.category === 'compliance');

  for (const finding of complianceFindings) {
    if (finding.count === 0) {
      if (finding.type.startsWith('ANSSI_')) anssi.passed++;
      else if (finding.type.startsWith('NIST_')) nist.passed++;
      else if (finding.type.startsWith('CIS_')) cis.passed++;
      else if (finding.type.startsWith('DISA_')) disa.passed++;
      else if (industryTypes.includes(finding.type)) industry.passed++;
    }
  }

  // Calculate overall score
  const totalControls = anssi.total + nist.total + cis.total + disa.total + industry.total;
  const passedControls = anssi.passed + nist.passed + cis.passed + disa.passed + industry.passed;
  const compliancePercentage = Math.round((passedControls / totalControls) * 100);

  return {
    type: 'COMPLIANCE_SCORE',
    severity: 'low',
    category: 'compliance',
    title: 'Compliance Score Summary',
    description: `Overall compliance score: ${compliancePercentage}%. This represents adherence to ANSSI, NIST, CIS, DISA, and industry frameworks (PCI-DSS, SOC2, GDPR, SOX, DORA, HIPAA, ISO27001).`,
    count: totalControls - passedControls, // Non-compliant controls
    details: {
      score: compliancePercentage,
      frameworks: {
        ANSSI: `${anssi.passed}/${anssi.total}`,
        NIST: `${nist.passed}/${nist.total}`,
        CIS: `${cis.passed}/${cis.total}`,
        DISA: `${disa.passed}/${disa.total}`,
        'Industry (PCI/SOC2/GDPR/SOX/DORA/HIPAA/ISO)': `${industry.passed}/${industry.total}`,
      },
      passedControls,
      totalControls,
      recommendation:
        compliancePercentage < 70
          ? 'Compliance score is below 70%. Prioritize addressing high-severity compliance gaps.'
          : undefined,
    },
  };
}

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
