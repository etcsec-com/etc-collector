/**
 * Password Security Vulnerability Detector
 *
 * Detects password-related vulnerabilities in AD users.
 * Story 1.7: AD Vulnerability Detection Engine
 *
 * Vulnerabilities detected (11):
 * - PASSWORD_NOT_REQUIRED (Critical)
 * - REVERSIBLE_ENCRYPTION (Critical)
 * - PASSWORD_NEVER_EXPIRES (Critical)
 * - PASSWORD_VERY_OLD (Medium)
 * - PASSWORD_IN_DESCRIPTION (High)
 * - USER_CANNOT_CHANGE_PASSWORD (Medium)
 * - UNIX_USER_PASSWORD (Critical)
 * - WEAK_PASSWORD_POLICY (High - domain level)
 * - PASSWORD_CLEARTEXT_STORAGE (Critical) - Phase 3
 * - PASSWORD_COMMON_PATTERNS (High) - Phase 3
 * - PASSWORD_DICT_ATTACK_RISK (Medium) - Phase 3
 */

import { ADUser } from '../../../../types/ad.types';
import { Finding } from '../../../../types/finding.types';
import { toAffectedUserEntities, ldapAttrToString } from '../../../../utils/entity-converter';

/**
 * Check if password is not required (UAC flag 0x20)
 */
export function detectPasswordNotRequired(users: ADUser[], includeDetails: boolean): Finding {
  const affected = users.filter((u) => {
    if (!u.userAccountControl) return false;
    return (u.userAccountControl & 0x20) !== 0; // PASSWD_NOTREQD
  });

  return {
    type: 'PASSWORD_NOT_REQUIRED',
    severity: 'critical',
    category: 'passwords',
    title: 'Password Not Required',
    description: 'User accounts that do not require a password (UAC flag 0x20). Attackers can authenticate without credentials.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected) : undefined,
  };
}

/**
 * Check if password stored with reversible encryption (UAC flag 0x80)
 */
export function detectReversibleEncryption(users: ADUser[], includeDetails: boolean): Finding {
  const affected = users.filter((u) => {
    if (!u.userAccountControl) return false;
    return (u.userAccountControl & 0x80) !== 0; // ENCRYPTED_TEXT_PASSWORD_ALLOWED
  });

  return {
    type: 'REVERSIBLE_ENCRYPTION',
    severity: 'critical',
    category: 'passwords',
    title: 'Reversible Encryption',
    description: 'Passwords stored with reversible encryption (UAC flag 0x80). Equivalent to storing passwords in cleartext.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected) : undefined,
  };
}

/**
 * Check if password never expires (UAC flag 0x10000)
 */
export function detectPasswordNeverExpires(users: ADUser[], includeDetails: boolean): Finding {
  const affected = users.filter((u) => {
    if (!u.userAccountControl) return false;
    return (u.userAccountControl & 0x10000) !== 0; // DONT_EXPIRE_PASSWD
  });

  return {
    type: 'PASSWORD_NEVER_EXPIRES',
    severity: 'critical',
    category: 'passwords',
    title: 'Password Never Expires',
    description: 'User accounts with passwords set to never expire (UAC flag 0x10000). Old passwords increase breach risk.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected) : undefined,
  };
}

/**
 * Check if password is very old (>365 days)
 */
export function detectPasswordVeryOld(users: ADUser[], includeDetails: boolean): Finding {
  const now = Date.now();
  const oneYearAgo = now - 365 * 24 * 60 * 60 * 1000;

  const affected = users.filter((u) => {
    if (!u.passwordLastSet) return false;
    return u.passwordLastSet.getTime() < oneYearAgo;
  });

  return {
    type: 'PASSWORD_VERY_OLD',
    severity: 'medium',
    category: 'passwords',
    title: 'Password Very Old',
    description: 'User accounts with passwords older than 365 days. Increases risk of credential compromise.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected) : undefined,
  };
}

/**
 * Check if password is in description field
 */
export function detectPasswordInDescription(users: ADUser[], includeDetails: boolean): Finding {
  const passwordPatterns = [
    /password\s*[:=]\s*\S+/i,
    /pwd\s*[:=]\s*\S+/i,
    /pass\s*[:=]\s*\S+/i,
    /motdepasse\s*[:=]\s*\S+/i,
    /\bP@ssw0rd\b/i,
    /\bPassword123\b/i,
  ];

  const affected = users.filter((u) => {
    const description = ldapAttrToString((u as any)['description']);
    if (!description) return false;
    return passwordPatterns.some((pattern) => pattern.test(description));
  });

  return {
    type: 'PASSWORD_IN_DESCRIPTION',
    severity: 'high',
    category: 'passwords',
    title: 'Password in Description',
    description: 'User accounts with passwords or password-like strings in the description field. Cleartext credential exposure.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected) : undefined,
  };
}

/**
 * Check if user cannot change password (UAC flag 0x40)
 */
export function detectUserCannotChangePassword(users: ADUser[], includeDetails: boolean): Finding {
  const affected = users.filter((u) => {
    if (!u.userAccountControl) return false;
    return (u.userAccountControl & 0x40) !== 0; // PASSWD_CANT_CHANGE
  });

  return {
    type: 'USER_CANNOT_CHANGE_PASSWORD',
    severity: 'medium',
    category: 'passwords',
    title: 'User Cannot Change Password',
    description: 'User accounts forbidden from changing their own password (UAC flag 0x40). Prevents password rotation.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected) : undefined,
  };
}

/**
 * Check for Unix password attributes (cleartext)
 */
export function detectUnixUserPassword(users: ADUser[], includeDetails: boolean): Finding {
  const affected = users.filter((u) => {
    // Check for unixUserPassword or userPassword attributes
    return 'unixUserPassword' in u || 'userPassword' in u;
  });

  return {
    type: 'UNIX_USER_PASSWORD',
    severity: 'critical',
    category: 'passwords',
    title: 'Unix User Password',
    description: 'User accounts with Unix password attributes present. These may contain cleartext or weakly hashed passwords.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected) : undefined,
  };
}

/**
 * Check for cleartext password storage attributes
 *
 * Detects accounts with attributes that may store passwords in cleartext
 * or reversible format (supplementalCredentials, userPassword, etc.)
 *
 * @param users - Array of AD users
 * @param includeDetails - Whether to include affected entity details
 * @returns Finding for PASSWORD_CLEARTEXT_STORAGE
 */
export function detectPasswordCleartextStorage(users: ADUser[], includeDetails: boolean): Finding {
  const cleartextAttributes = [
    'unixUserPassword',
    'userPassword',
    'unicodePwd', // Should never be readable
    'msDS-ManagedPassword', // gMSA - should be protected
    'ms-Mcs-AdmPwd', // LAPS - cleartext by design, but should be protected
  ];

  const affected = users.filter((u) => {
    // Check if any cleartext password attribute exists and has a value
    return cleartextAttributes.some((attr) => {
      const value = (u as Record<string, unknown>)[attr];
      return value !== undefined && value !== null && value !== '';
    });
  });

  return {
    type: 'PASSWORD_CLEARTEXT_STORAGE',
    severity: 'critical',
    category: 'passwords',
    title: 'Cleartext Password Storage',
    description:
      'User accounts with attributes that may store passwords in cleartext or reversible format. ' +
      'These attributes (userPassword, unixUserPassword) can be read by attackers with LDAP access.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected) : undefined,
  };
}

/**
 * Check for common password patterns in account names
 *
 * Accounts with names suggesting default/weak passwords.
 *
 * @param users - Array of AD users
 * @param includeDetails - Whether to include affected entity details
 * @returns Finding for PASSWORD_COMMON_PATTERNS
 */
export function detectPasswordCommonPatterns(users: ADUser[], includeDetails: boolean): Finding {
  // Patterns that suggest default or weak passwords
  const riskyNamePatterns = [
    /^admin$/i,
    /^administrator$/i,
    /^test$/i,
    /^user$/i,
    /^guest$/i,
    /^temp$/i,
    /^default$/i,
    /^support$/i,
    /^service$/i,
    /^backup$/i,
    /^demo$/i,
    /password/i,
    /123$/,
    /^sa$/i,
    /^dba$/i,
  ];

  const affected = users.filter((u) => {
    if (!u.enabled) return false;
    const samName = u.sAMAccountName.toLowerCase();
    return riskyNamePatterns.some((pattern) => pattern.test(samName));
  });

  return {
    type: 'PASSWORD_COMMON_PATTERNS',
    severity: 'high',
    category: 'passwords',
    title: 'Common Password Pattern Risk',
    description:
      'User accounts with names suggesting default or commonly-used passwords (admin, test, user, temp). ' +
      'These accounts are primary targets for password spraying attacks.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected) : undefined,
    details: {
      affectedAccountNames: affected.slice(0, 10).map((u) => u.sAMAccountName),
    },
  };
}

/**
 * Check for dictionary attack risk
 *
 * Accounts with low bad password count threshold allowing dictionary attacks.
 *
 * @param users - Array of AD users
 * @param includeDetails - Whether to include affected entity details
 * @returns Finding for PASSWORD_DICT_ATTACK_RISK
 */
export function detectPasswordDictAttackRisk(users: ADUser[], includeDetails: boolean): Finding {
  // Accounts that have been locked out or have high bad password count
  // This indicates they may have weak passwords being targeted
  const affected = users.filter((u) => {
    if (!u.enabled) return false;
    const badPwdCount = u.badPwdCount ?? 0;
    const lockoutTime = u.lockoutTime;

    // Account has been targeted (>3 bad password attempts) or is currently locked
    return badPwdCount > 3 || (lockoutTime && lockoutTime !== '0');
  });

  return {
    type: 'PASSWORD_DICT_ATTACK_RISK',
    severity: 'medium',
    category: 'passwords',
    title: 'Dictionary Attack Risk',
    description:
      'User accounts showing signs of password guessing attacks (multiple bad password attempts or lockouts). ' +
      'May indicate weak passwords being targeted or ongoing brute-force attacks.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected) : undefined,
    details: {
      recommendation:
        'Review affected accounts for weak passwords. Consider implementing Azure AD Password Protection.',
    },
  };
}

/**
 * Detect all password-related vulnerabilities
 */
export function detectPasswordVulnerabilities(users: ADUser[], includeDetails: boolean): Finding[] {
  return [
    detectPasswordNotRequired(users, includeDetails),
    detectReversibleEncryption(users, includeDetails),
    detectPasswordNeverExpires(users, includeDetails),
    detectPasswordVeryOld(users, includeDetails),
    detectPasswordInDescription(users, includeDetails),
    detectUserCannotChangePassword(users, includeDetails),
    detectUnixUserPassword(users, includeDetails),
    // Phase 3 additions
    detectPasswordCleartextStorage(users, includeDetails),
    detectPasswordCommonPatterns(users, includeDetails),
    detectPasswordDictAttackRisk(users, includeDetails),
  ].filter((finding) => finding.count > 0); // Only return findings with affected entities
}
