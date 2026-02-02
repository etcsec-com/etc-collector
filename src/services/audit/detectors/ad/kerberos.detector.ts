/**
 * Kerberos Security Vulnerability Detector
 *
 * Detects Kerberos-related vulnerabilities in AD.
 * Story 1.7: AD Vulnerability Detection Engine
 *
 * Vulnerabilities detected (12):
 * - ASREP_ROASTING_RISK (Critical)
 * - UNCONSTRAINED_DELEGATION (Critical)
 * - GOLDEN_TICKET_RISK (Critical)
 * - KERBEROASTING_RISK (High)
 * - CONSTRAINED_DELEGATION (High)
 * - WEAK_ENCRYPTION_DES (High)
 * - WEAK_ENCRYPTION_RC4 (Medium)
 * - WEAK_ENCRYPTION_FLAG (Medium)
 * - KERBEROS_AES_DISABLED (High) - Phase 4
 * - KERBEROS_RC4_FALLBACK (Medium) - Phase 4
 * - KERBEROS_TICKET_LIFETIME_LONG (Medium) - Phase 4
 * - KERBEROS_RENEWABLE_TICKET_LONG (Low) - Phase 4
 */

import { ADUser } from '../../../../types/ad.types';
import { Finding } from '../../../../types/finding.types';
import { toAffectedUserEntities } from '../../../../utils/entity-converter';

/**
 * Check for ASREP roasting risk (no Kerberos pre-authentication)
 * UAC flag 0x400000 = DONT_REQ_PREAUTH
 */
export function detectAsrepRoastingRisk(users: ADUser[], includeDetails: boolean): Finding {
  const affected = users.filter((u) => {
    if (!u.userAccountControl) return false;
    return (u.userAccountControl & 0x400000) !== 0;
  });

  return {
    type: 'ASREP_ROASTING_RISK',
    severity: 'critical',
    category: 'kerberos',
    title: 'AS-REP Roasting Risk',
    description: 'User accounts without Kerberos pre-authentication required (UAC 0x400000). Vulnerable to AS-REP roasting attacks.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected) : undefined,
  };
}

/**
 * Check for unconstrained delegation
 * UAC flag 0x80000 = TRUSTED_FOR_DELEGATION
 */
export function detectUnconstrainedDelegation(users: ADUser[], includeDetails: boolean): Finding {
  const affected = users.filter((u) => {
    if (!u.userAccountControl) return false;
    return (u.userAccountControl & 0x80000) !== 0;
  });

  return {
    type: 'UNCONSTRAINED_DELEGATION',
    severity: 'critical',
    category: 'kerberos',
    title: 'Unconstrained Delegation',
    description: 'User accounts with unconstrained Kerberos delegation enabled (UAC 0x80000). Can impersonate any user.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected) : undefined,
  };
}

/**
 * Check for Golden Ticket risk (krbtgt password old)
 */
export function detectGoldenTicketRisk(users: ADUser[], includeDetails: boolean): Finding {
  const krbtgtAccount = users.find((u) => u.sAMAccountName === 'krbtgt');

  if (!krbtgtAccount || !krbtgtAccount.passwordLastSet) {
    return {
      type: 'GOLDEN_TICKET_RISK',
      severity: 'critical',
      category: 'kerberos',
      title: 'Golden Ticket Risk',
      description: 'krbtgt account password unchanged for 180+ days or password date unavailable. Enables persistent Golden Ticket attacks.',
      count: 0,
    };
  }

  const now = Date.now();
  const sixMonthsAgo = now - 180 * 24 * 60 * 60 * 1000;
  const passwordAge = krbtgtAccount.passwordLastSet.getTime();
  const isOld = passwordAge < sixMonthsAgo;

  return {
    type: 'GOLDEN_TICKET_RISK',
    severity: 'critical',
    category: 'kerberos',
    title: 'Golden Ticket Risk',
    description: `krbtgt account password unchanged for 180+ days. Enables persistent Golden Ticket attacks.`,
    count: isOld ? 1 : 0,
    affectedEntities: includeDetails && isOld ? [krbtgtAccount.dn] : undefined,
  };
}

/**
 * Check for Kerberoasting risk (user with SPN)
 */
export function detectKerberoastingRisk(users: ADUser[], includeDetails: boolean): Finding {
  const affected = users.filter((u) => {
    const spns = (u as any)['servicePrincipalName'];
    return spns && Array.isArray(spns) && spns.length > 0;
  });

  return {
    type: 'KERBEROASTING_RISK',
    severity: 'high',
    category: 'kerberos',
    title: 'Kerberoasting Risk',
    description: 'User accounts with Service Principal Names (SPNs). Vulnerable to Kerberoasting attacks to crack service account passwords.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected) : undefined,
  };
}

/**
 * Check for constrained delegation
 * UAC flag 0x1000000 = TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION
 */
export function detectConstrainedDelegation(users: ADUser[], includeDetails: boolean): Finding {
  const affected = users.filter((u) => {
    if (!u.userAccountControl) return false;
    return (u.userAccountControl & 0x1000000) !== 0;
  });

  return {
    type: 'CONSTRAINED_DELEGATION',
    severity: 'high',
    category: 'kerberos',
    title: 'Constrained Delegation',
    description: 'User accounts with constrained Kerberos delegation configured (UAC 0x1000000). Can impersonate users to specific services.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected) : undefined,
  };
}

/**
 * Check for weak DES encryption
 * Checks both UAC flag 0x200000 (USE_DES_KEY_ONLY) and msDS-SupportedEncryptionTypes
 * DES_CBC_CRC = 0x1, DES_CBC_MD5 = 0x2
 */
export function detectWeakEncryptionDES(users: ADUser[], includeDetails: boolean): Finding {
  const DES_TYPES = 0x3; // DES_CBC_CRC (0x1) | DES_CBC_MD5 (0x2)

  const affected = users.filter((u) => {
    // Check UAC flag USE_DES_KEY_ONLY
    if (u.userAccountControl && (u.userAccountControl & 0x200000) !== 0) {
      return true;
    }
    // Check msDS-SupportedEncryptionTypes for DES support
    const encTypes = (u as any)['msDS-SupportedEncryptionTypes'];
    if (typeof encTypes === 'number' && (encTypes & DES_TYPES) !== 0) {
      return true;
    }
    return false;
  });

  return {
    type: 'WEAK_ENCRYPTION_DES',
    severity: 'high',
    category: 'kerberos',
    title: 'Weak DES Encryption',
    description: 'User accounts with DES encryption algorithms enabled (UAC 0x200000 or msDS-SupportedEncryptionTypes). DES is cryptographically broken.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected) : undefined,
  };
}

/**
 * Check for privileged accounts vulnerable to AS-REP Roasting
 * High-value targets (Domain Admins, Enterprise Admins, etc.) without pre-auth
 */
export function detectAdminAsrepRoastable(users: ADUser[], includeDetails: boolean): Finding {
  const privilegedGroups = [
    'Domain Admins',
    'Enterprise Admins',
    'Schema Admins',
    'Administrators',
    'Account Operators',
    'Backup Operators',
    'Server Operators',
  ];

  const affected = users.filter((u) => {
    // Check for DONT_REQ_PREAUTH flag
    if (!u.userAccountControl || (u.userAccountControl & 0x400000) === 0) {
      return false;
    }
    // Check if user is in a privileged group
    if (!u.memberOf) return false;
    return u.memberOf.some((dn) =>
      privilegedGroups.some((group) => dn.toUpperCase().includes(`CN=${group.toUpperCase()}`))
    );
  });

  return {
    type: 'ADMIN_ASREP_ROASTABLE',
    severity: 'critical',
    category: 'kerberos',
    title: 'Privileged Account AS-REP Roastable',
    description:
      'Privileged accounts (Domain Admins, Enterprise Admins, etc.) without Kerberos pre-authentication. ' +
      'High-value targets for AS-REP roasting attacks - immediate domain compromise risk.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected) : undefined,
    details: affected.length > 0 ? {
      risk: 'CRITICAL - Privileged account password hash can be obtained offline',
      recommendation: 'Enable Kerberos pre-authentication immediately for all privileged accounts',
    } : undefined,
  };
}

/**
 * Check for RC4-only encryption (no AES)
 */
export function detectWeakEncryptionRC4(users: ADUser[], includeDetails: boolean): Finding {
  const affected = users.filter((u) => {
    const encTypes = (u as any)['msDS-SupportedEncryptionTypes'];
    if (typeof encTypes !== 'number') return false;
    return (encTypes & 4) !== 0 && (encTypes & 24) === 0;
  });

  return {
    type: 'WEAK_ENCRYPTION_RC4',
    severity: 'medium',
    category: 'kerberos',
    title: 'Weak RC4 Encryption',
    description: 'User accounts supporting RC4 encryption without AES. RC4 is deprecated and vulnerable to attacks.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected) : undefined,
  };
}

/**
 * Check for USE_DES_KEY_ONLY flag
 */
export function detectWeakEncryptionFlag(users: ADUser[], includeDetails: boolean): Finding {
  const affected = users.filter((u) => {
    if (!u.userAccountControl) return false;
    return (u.userAccountControl & 0x200000) !== 0;
  });

  return {
    type: 'WEAK_ENCRYPTION_FLAG',
    severity: 'medium',
    category: 'kerberos',
    title: 'Weak Encryption Flag',
    description: 'User accounts with USE_DES_KEY_ONLY flag enabled (UAC 0x200000). Forces weak DES encryption.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected) : undefined,
  };
}

/**
 * Detect accounts with AES encryption disabled
 *
 * Accounts without AES support are limited to weaker DES/RC4 encryption,
 * making them vulnerable to offline cracking attacks.
 *
 * @param users - Array of AD users
 * @param includeDetails - Whether to include affected entity details
 * @returns Finding for KERBEROS_AES_DISABLED
 */
export function detectKerberosAesDisabled(users: ADUser[], includeDetails: boolean): Finding {
  // msDS-SupportedEncryptionTypes: AES128=0x8, AES256=0x10
  const AES_SUPPORT = 0x18;

  const affected = users.filter((u) => {
    if (!u.enabled) return false;
    const encTypes = (u as Record<string, unknown>)['msDS-SupportedEncryptionTypes'] as
      | number
      | undefined;
    // If explicitly set and doesn't include AES
    if (encTypes !== undefined && (encTypes & AES_SUPPORT) === 0) {
      return true;
    }
    // If UAC indicates DES-only (0x200000 = USE_DES_KEY_ONLY)
    if (u.userAccountControl && (u.userAccountControl & 0x200000) !== 0) {
      return true;
    }
    return false;
  });

  return {
    type: 'KERBEROS_AES_DISABLED',
    severity: 'high',
    category: 'kerberos',
    title: 'AES Encryption Disabled',
    description:
      'User accounts with AES Kerberos encryption disabled. ' +
      'Forces use of weaker DES/RC4 encryption vulnerable to offline attacks.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected) : undefined,
  };
}

/**
 * Detect accounts with RC4 fallback enabled
 *
 * While AES may be supported, RC4 fallback allows downgrade attacks.
 *
 * @param users - Array of AD users
 * @param includeDetails - Whether to include affected entity details
 * @returns Finding for KERBEROS_RC4_FALLBACK
 */
export function detectKerberosRc4Fallback(users: ADUser[], includeDetails: boolean): Finding {
  // RC4_HMAC_MD5 = 0x4
  const RC4_SUPPORT = 0x4;
  const AES_SUPPORT = 0x18;

  const affected = users.filter((u) => {
    if (!u.enabled) return false;
    const encTypes = (u as Record<string, unknown>)['msDS-SupportedEncryptionTypes'] as
      | number
      | undefined;
    if (encTypes === undefined) return false;
    // Has both AES and RC4 - RC4 should be disabled
    const hasAes = (encTypes & AES_SUPPORT) !== 0;
    const hasRc4 = (encTypes & RC4_SUPPORT) !== 0;
    return hasAes && hasRc4;
  });

  return {
    type: 'KERBEROS_RC4_FALLBACK',
    severity: 'medium',
    category: 'kerberos',
    title: 'RC4 Fallback Enabled',
    description:
      'User accounts support both AES and RC4 encryption. ' +
      'RC4 fallback enables downgrade attacks even when AES is available.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected) : undefined,
    details: {
      recommendation: 'Disable RC4 support when AES is available.',
    },
  };
}

/**
 * Detect long Kerberos ticket lifetime (domain level)
 *
 * Very long ticket lifetimes increase the window for ticket theft attacks.
 *
 * @param _users - Array of AD users (not used, domain-level check)
 * @param _includeDetails - Whether to include affected entity details
 * @returns Finding for KERBEROS_TICKET_LIFETIME_LONG
 */
export function detectKerberosTicketLifetimeLong(
  _users: ADUser[],
  _includeDetails: boolean
): Finding {
  // This detection would need domain Kerberos policy data
  // For now, return a placeholder that reminds to check
  return {
    type: 'KERBEROS_TICKET_LIFETIME_LONG',
    severity: 'medium',
    category: 'kerberos',
    title: 'Kerberos Ticket Lifetime Review',
    description:
      'Kerberos ticket lifetime should be reviewed. ' +
      'Default of 10 hours is reasonable; longer lifetimes increase attack window.',
    count: 0, // Would be 1 if ticket lifetime > 10 hours detected
    details: {
      recommendation: 'TGT lifetime should not exceed 10 hours. Service tickets should not exceed 600 minutes.',
      checkCommand: 'gpresult /r or check Default Domain Policy',
    },
  };
}

/**
 * Detect long renewable ticket lifetime
 *
 * Very long renewable ticket lifetimes allow persistent access.
 *
 * @param _users - Array of AD users (not used, domain-level check)
 * @param _includeDetails - Whether to include affected entity details
 * @returns Finding for KERBEROS_RENEWABLE_TICKET_LONG
 */
export function detectKerberosRenewableTicketLong(
  _users: ADUser[],
  _includeDetails: boolean
): Finding {
  // This detection would need domain Kerberos policy data
  return {
    type: 'KERBEROS_RENEWABLE_TICKET_LONG',
    severity: 'low',
    category: 'kerberos',
    title: 'Kerberos Renewable Ticket Lifetime Review',
    description:
      'Renewable ticket lifetime should be reviewed. ' +
      'Default of 7 days is reasonable; longer allows persistent access with stolen tickets.',
    count: 0, // Would be 1 if renewable lifetime > 7 days detected
    details: {
      recommendation: 'Renewable TGT lifetime should not exceed 7 days.',
    },
  };
}

/**
 * Detect all Kerberos-related vulnerabilities
 */
export function detectKerberosVulnerabilities(users: ADUser[], includeDetails: boolean): Finding[] {
  return [
    detectAsrepRoastingRisk(users, includeDetails),
    detectAdminAsrepRoastable(users, includeDetails), // NEW: Privileged accounts with ASREP risk
    detectUnconstrainedDelegation(users, includeDetails),
    detectGoldenTicketRisk(users, includeDetails),
    detectKerberoastingRisk(users, includeDetails),
    detectConstrainedDelegation(users, includeDetails),
    detectWeakEncryptionDES(users, includeDetails),
    detectWeakEncryptionRC4(users, includeDetails),
    detectWeakEncryptionFlag(users, includeDetails),
    // Phase 4: Advanced Kerberos detections
    detectKerberosAesDisabled(users, includeDetails),
    detectKerberosRc4Fallback(users, includeDetails),
    detectKerberosTicketLifetimeLong(users, includeDetails),
    detectKerberosRenewableTicketLong(users, includeDetails),
  ].filter((finding) => finding.count > 0);
}
