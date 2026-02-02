/**
 * Computers Security Vulnerability Detector
 *
 * Detects computer-related vulnerabilities in AD.
 * Story 1.7: AD Vulnerability Detection Engine
 *
 * Vulnerabilities detected (28):
 * - COMPUTER_CONSTRAINED_DELEGATION (Critical)
 * - COMPUTER_RBCD (Critical)
 * - COMPUTER_IN_ADMIN_GROUP (Critical)
 * - COMPUTER_DCSYNC_RIGHTS (Critical)
 * - COMPUTER_UNCONSTRAINED_DELEGATION (Critical)
 * - COMPUTER_OS_OBSOLETE_XP (Critical)
 * - COMPUTER_OS_OBSOLETE_2003 (Critical)
 * - COMPUTER_STALE_INACTIVE (High)
 * - COMPUTER_PASSWORD_OLD (High)
 * - COMPUTER_WITH_SPNS (High)
 * - COMPUTER_NO_LAPS (High)
 * - COMPUTER_ACL_ABUSE (High)
 * - COMPUTER_OS_OBSOLETE_2008 (High)
 * - COMPUTER_OS_OBSOLETE_VISTA (High)
 * - DC_NOT_IN_DC_OU (High) - Phase 2C
 * - COMPUTER_NO_BITLOCKER (High) - Phase 4
 * - COMPUTER_DISABLED_NOT_DELETED (Medium)
 * - COMPUTER_WRONG_OU (Medium)
 * - COMPUTER_WEAK_ENCRYPTION (Medium)
 * - COMPUTER_DESCRIPTION_SENSITIVE (Medium)
 * - COMPUTER_PRE_WINDOWS_2000 (Medium)
 * - COMPUTER_NEVER_LOGGED_ON (Medium)
 * - COMPUTER_DUPLICATE_SPN (Medium) - Phase 2C
 * - SERVER_NO_ADMIN_GROUP (Medium) - Phase 2C
 * - COMPUTER_LEGACY_PROTOCOL (Medium) - Phase 4
 * - COMPUTER_ADMIN_COUNT (Low)
 * - COMPUTER_SMB_SIGNING_DISABLED (Low)
 * - WORKSTATION_IN_SERVER_OU (Low) - Phase 2C
 */

import { ADComputer } from '../../../../types/ad.types';
import { Finding } from '../../../../types/finding.types';
import { toAffectedComputerEntities, ldapAttrToString } from '../../../../utils/entity-converter';

/**
 * Windows FILETIME epoch offset in milliseconds
 * Difference between 1601-01-01 and 1970-01-01
 */
const FILETIME_EPOCH_OFFSET = 11644473600000;

/**
 * Convert any date format to timestamp in milliseconds
 * Handles: Date object, ISO string, FILETIME (number/string), undefined/null
 *
 * @param value - Date in any format
 * @returns Timestamp in milliseconds, or null if invalid
 */
function toTimestamp(value: any): number | null {
  if (!value) return null;

  // Already a Date object
  if (value instanceof Date) {
    const time = value.getTime();
    return isNaN(time) ? null : time;
  }

  // String value
  if (typeof value === 'string') {
    // Try ISO date first (e.g., "2024-01-15T10:30:00.000Z")
    if (value.includes('-') && value.includes('T')) {
      const date = new Date(value);
      const time = date.getTime();
      return isNaN(time) ? null : time;
    }

    // Try LDAP generalizedTime format (e.g., "20260115123456.0Z" or "20260115123456Z")
    const gtMatch = value.match(/^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})/);
    if (gtMatch && gtMatch[1] && gtMatch[2] && gtMatch[3] && gtMatch[4] && gtMatch[5] && gtMatch[6]) {
      const date = new Date(
        Date.UTC(
          parseInt(gtMatch[1], 10),
          parseInt(gtMatch[2], 10) - 1,
          parseInt(gtMatch[3], 10),
          parseInt(gtMatch[4], 10),
          parseInt(gtMatch[5], 10),
          parseInt(gtMatch[6], 10)
        )
      );
      const time = date.getTime();
      return isNaN(time) ? null : time;
    }

    // Try as numeric FILETIME string
    const parsed = parseInt(value, 10);
    if (!isNaN(parsed) && parsed > 0) {
      return filetimeToTimestamp(parsed);
    }
    return null;
  }

  // Number - could be FILETIME or Unix timestamp
  if (typeof value === 'number') {
    if (value <= 0) return null;
    // FILETIME values are huge (> 100 trillion), Unix timestamps are ~1.7 trillion ms
    if (value > 100000000000000) {
      return filetimeToTimestamp(value);
    }
    // If it's reasonable (after year 2000 and before year 2100)
    if (value > 946684800000 && value < 4102444800000) {
      return value; // Already a Unix timestamp in ms
    }
    // Could be Unix seconds
    if (value > 946684800 && value < 4102444800) {
      return value * 1000;
    }
    // Assume FILETIME
    return filetimeToTimestamp(value);
  }

  return null;
}

/**
 * Convert Windows FILETIME to Unix timestamp in milliseconds
 */
function filetimeToTimestamp(filetime: number): number | null {
  // Invalid or "Never" values
  if (filetime === 0 || filetime >= Number.MAX_SAFE_INTEGER) {
    return null;
  }

  // Convert 100-ns intervals to milliseconds and adjust epoch
  const ms = filetime / 10000 - FILETIME_EPOCH_OFFSET;

  // Validate reasonable range (year 1970 to 2100)
  if (ms < 0 || ms > 4102444800000) {
    return null;
  }

  return ms;
}

/**
 * Check for computer with constrained delegation
 */
export function detectComputerConstrainedDelegation(
  computers: ADComputer[],
  includeDetails: boolean
): Finding {
  const affected = computers.filter((c) => {
    const delegateTo = (c as any)['msDS-AllowedToDelegateTo'];
    // Check that attribute exists, is not null, not empty string, and not empty array
    return delegateTo && (Array.isArray(delegateTo) ? delegateTo.length > 0 : delegateTo !== '');
  });

  return {
    type: 'COMPUTER_CONSTRAINED_DELEGATION',
    severity: 'critical',
    category: 'computers',
    title: 'Computer Constrained Delegation',
    description: 'Computer with constrained Kerberos delegation. Can impersonate users to specified services.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedComputerEntities(affected) : undefined,
  };
}

/**
 * Check for computer with RBCD configured
 */
export function detectComputerRbcd(computers: ADComputer[], includeDetails: boolean): Finding {
  const affected = computers.filter((c) => {
    const rbcdAttr = (c as any)['msDS-AllowedToActOnBehalfOfOtherIdentity'];
    // Check that attribute exists, is not null, not empty string, and not empty array
    return rbcdAttr && (Array.isArray(rbcdAttr) ? rbcdAttr.length > 0 : rbcdAttr !== '');
  });

  return {
    type: 'COMPUTER_RBCD',
    severity: 'critical',
    category: 'computers',
    title: 'Computer RBCD',
    description: 'Computer with Resource-Based Constrained Delegation. Enables privilege escalation via RBCD attack.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedComputerEntities(affected) : undefined,
  };
}

/**
 * Check for computer in admin groups
 */
export function detectComputerInAdminGroup(computers: ADComputer[], includeDetails: boolean): Finding {
  const adminGroups = ['Domain Admins', 'Enterprise Admins'];

  const affected = computers.filter((c) => {
    const memberOf = (c as any).memberOf;
    if (!memberOf) return false;
    return memberOf.some((dn: string) => adminGroups.some((group) => dn.includes(`CN=${group}`)));
  });

  return {
    type: 'COMPUTER_IN_ADMIN_GROUP',
    severity: 'critical',
    category: 'computers',
    title: 'Computer in Admin Group',
    description: 'Computer account in Domain Admins or Enterprise Admins. Computer compromise leads to domain admin access.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedComputerEntities(affected) : undefined,
  };
}

/**
 * Check for computer with DCSync rights
 */
export function detectComputerDcsyncRights(computers: ADComputer[], includeDetails: boolean): Finding {
  // Note: This requires ACL analysis which would be done in permissions detector
  // For now, we detect computers with the replication rights attribute
  const affected = computers.filter((c) => {
    return 'replicationRights' in c && (c as any).replicationRights;
  });

  return {
    type: 'COMPUTER_DCSYNC_RIGHTS',
    severity: 'critical',
    category: 'computers',
    title: 'Computer DCSync Rights',
    description: 'Computer with DCSync replication rights. Can extract all domain password hashes.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedComputerEntities(affected) : undefined,
  };
}

/**
 * Check for computer with unconstrained delegation
 */
export function detectComputerUnconstrainedDelegation(
  computers: ADComputer[],
  includeDetails: boolean
): Finding {
  const affected = computers.filter((c) => {
    const uac = (c as any).userAccountControl;
    if (!uac) return false;
    return (uac & 0x80000) !== 0; // TRUSTED_FOR_DELEGATION
  });

  return {
    type: 'COMPUTER_UNCONSTRAINED_DELEGATION',
    severity: 'critical',
    category: 'computers',
    title: 'Computer Unconstrained Delegation',
    description: 'Computer with unconstrained delegation enabled. Servers can be used for privilege escalation attacks.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedComputerEntities(affected) : undefined,
  };
}

/**
 * Check for stale/inactive computers (90+ days)
 * Note: Computers that have NEVER logged on are handled by COMPUTER_NEVER_LOGGED_ON
 */
export function detectComputerStaleInactive(computers: ADComputer[], includeDetails: boolean): Finding {
  const now = Date.now();
  const ninetyDaysAgo = now - 90 * 24 * 60 * 60 * 1000;

  const affected = computers.filter((c) => {
    // Only check enabled computers
    if (!c.enabled) return false;

    // Try lastLogon first, then lastLogonTimestamp (replicated, more reliable)
    const lastLogonTime =
      toTimestamp(c.lastLogon) ?? toTimestamp((c as any)['lastLogonTimestamp']);

    // Skip if no logon time (handled by COMPUTER_NEVER_LOGGED_ON)
    if (!lastLogonTime) return false;

    return lastLogonTime < ninetyDaysAgo;
  });

  return {
    type: 'COMPUTER_STALE_INACTIVE',
    severity: 'high',
    category: 'computers',
    title: 'Computer Stale/Inactive',
    description: 'Computer inactive for 90+ days. Orphaned computer accounts could be exploited without detection.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedComputerEntities(affected) : undefined,
  };
}

/**
 * Check for computer with old password (>90 days)
 */
export function detectComputerPasswordOld(computers: ADComputer[], includeDetails: boolean): Finding {
  const now = Date.now();
  const ninetyDaysAgo = now - 90 * 24 * 60 * 60 * 1000;

  // Debug: track why computers are filtered out
  let debugStats = { total: 0, disabled: 0, noPwdLastSet: 0, recent: 0, old: 0 };

  const affected = computers.filter((c) => {
    debugStats.total++;
    // Only check enabled computers
    if (!c.enabled) {
      debugStats.disabled++;
      return false;
    }

    // Try pwdLastSet first, then passwordLastSet
    const pwdLastSet = toTimestamp((c as any).pwdLastSet) ?? toTimestamp((c as any).passwordLastSet);
    if (!pwdLastSet) {
      debugStats.noPwdLastSet++;
      return false;
    }

    if (pwdLastSet < ninetyDaysAgo) {
      debugStats.old++;
      return true;
    }
    debugStats.recent++;
    return false;
  });

  return {
    type: 'COMPUTER_PASSWORD_OLD',
    severity: 'high',
    category: 'computers',
    title: 'Computer Password Old',
    description: 'Computer password not changed for 90+ days. Increases risk of password-based attacks.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedComputerEntities(affected) : undefined,
    details: {
      debug: debugStats,
      threshold: '90 days',
      checkDate: new Date(ninetyDaysAgo).toISOString(),
    },
  };
}

/**
 * Check for computer with SPNs (Kerberoastable)
 */
export function detectComputerWithSpns(computers: ADComputer[], includeDetails: boolean): Finding {
  const affected = computers.filter((c) => {
    const spns = (c as any).servicePrincipalName;
    return spns && spns.length > 0;
  });

  return {
    type: 'COMPUTER_WITH_SPNS',
    severity: 'high',
    category: 'computers',
    title: 'Computer with SPNs',
    description: 'Computer with Service Principal Names. Enables Kerberoasting attack against computer account.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedComputerEntities(affected) : undefined,
  };
}

/**
 * Check for computer without LAPS
 * Checks for both legacy LAPS (ms-Mcs-AdmPwd) and Windows LAPS (msLAPS-Password)
 *
 * Note: Password attributes may not be readable without LAPS admin rights,
 * so we also check expiration time attributes which are more accessible.
 * If LAPS schema is not extended, ALL computers are flagged.
 */
export function detectComputerNoLaps(computers: ADComputer[], includeDetails: boolean): Finding {
  // Stats for debugging
  const total = computers.length;
  const disabled = computers.filter((c) => !c.enabled).length;
  const enabled = total - disabled;

  // Count DCs (SERVER_TRUST_ACCOUNT = 0x2000)
  const domainControllers = computers.filter((c) => {
    const uac = (c as any).userAccountControl;
    return uac && (uac & 0x2000) !== 0;
  }).length;

  // Check if any computer has LAPS attributes (indicates schema is extended)
  let hasLegacyLapsSchema = false;
  let hasWindowsLapsSchema = false;
  let withLegacyLaps = 0;
  let withWindowsLaps = 0;

  const affected = computers.filter((c) => {
    // Only check enabled computers (workstations and servers, not DCs)
    if (!c.enabled) return false;

    // Skip Domain Controllers (they don't use LAPS)
    const uac = (c as any).userAccountControl;
    if (uac && (uac & 0x2000) !== 0) return false; // SERVER_TRUST_ACCOUNT = DC

    const comp = c as Record<string, unknown>;

    // Check for legacy LAPS - password or expiration time
    // Note: LDAP may return [] for non-existent attributes, so check for actual values
    const legacyLaps = comp['ms-Mcs-AdmPwd'];
    const legacyLapsExpiry = comp['ms-Mcs-AdmPwdExpirationTime'];

    // Helper to check if value is a real LAPS value (not empty/null/undefined/[])
    const isValidLapsValue = (val: unknown): boolean => {
      if (val === undefined || val === null || val === '') return false;
      if (Array.isArray(val) && val.length === 0) return false;
      if (val === '0' || val === 0) return false;
      return true;
    };

    // Track if schema attributes exist with actual values
    if (isValidLapsValue(legacyLaps) || isValidLapsValue(legacyLapsExpiry)) {
      hasLegacyLapsSchema = true;
    }

    const hasLegacyLaps = isValidLapsValue(legacyLaps) || isValidLapsValue(legacyLapsExpiry);
    if (hasLegacyLaps) withLegacyLaps++;

    // Check for Windows LAPS - password or expiration time
    const windowsLaps = comp['msLAPS-Password'];
    const windowsLapsExpiry = comp['msLAPS-PasswordExpirationTime'];

    // Track if schema attributes exist with actual values
    if (isValidLapsValue(windowsLaps) || isValidLapsValue(windowsLapsExpiry)) {
      hasWindowsLapsSchema = true;
    }

    const hasWindowsLaps = isValidLapsValue(windowsLaps) || isValidLapsValue(windowsLapsExpiry);
    if (hasWindowsLaps) withWindowsLaps++;

    // No LAPS if neither legacy nor Windows LAPS is configured
    return !hasLegacyLaps && !hasWindowsLaps;
  });

  // Determine severity based on schema availability
  const schemaExtended = hasLegacyLapsSchema || hasWindowsLapsSchema;
  const eligibleComputers = enabled - domainControllers;

  return {
    type: 'COMPUTER_NO_LAPS',
    severity: !schemaExtended ? 'critical' : 'high', // Critical if schema not extended
    category: 'computers',
    title: !schemaExtended ? 'LAPS Not Deployed (Schema Not Extended)' : 'Computer No LAPS',
    description: !schemaExtended
      ? 'LAPS schema is not extended in Active Directory. ALL local admin passwords are unmanaged and likely shared across computers.'
      : 'Computer without LAPS deployed. Shared/static local admin passwords across workstations.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedComputerEntities(affected) : undefined,
    details: {
      debug: {
        total,
        enabled,
        disabled,
        domainControllers,
        eligibleComputers,
        withLegacyLaps,
        withWindowsLaps,
        withoutLaps: affected.length,
        schemaExtended,
        hasLegacyLapsSchema,
        hasWindowsLapsSchema,
      },
      recommendation: !schemaExtended
        ? 'Install LAPS (legacy or Windows LAPS) and extend the AD schema. Then deploy via GPO.'
        : 'Deploy LAPS to remaining computers via GPO.',
    },
  };
}

/**
 * Check for computer with ACL abuse potential
 */
export function detectComputerAclAbuse(computers: ADComputer[], includeDetails: boolean): Finding {
  // Note: This requires ACL analysis which would be done in permissions detector
  // For now, we detect computers with suspicious ACL attributes
  const affected = computers.filter((c) => {
    return 'dangerousAcl' in c && (c as any).dangerousAcl;
  });

  return {
    type: 'COMPUTER_ACL_ABUSE',
    severity: 'high',
    category: 'computers',
    title: 'Computer ACL Abuse',
    description: 'Computer with dangerous ACL permissions. Can modify computer object properties and escalate privileges.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedComputerEntities(affected) : undefined,
  };
}

/**
 * Check for disabled computers not deleted (>30 days)
 */
export function detectComputerDisabledNotDeleted(computers: ADComputer[], includeDetails: boolean): Finding {
  const now = Date.now();
  const thirtyDaysAgo = now - 30 * 24 * 60 * 60 * 1000;

  // Debug stats
  const debugStats: {
    total: number;
    enabled: number;
    noWhenChanged: number;
    recent: number;
    old: number;
    sampleDates: {
      name: string;
      raw: unknown;
      rawType: string;
      rawStringified: string;
      parsed: number | null;
      asIso: string | null;
      whenCreated: unknown;
    }[];
  } = { total: 0, enabled: 0, noWhenChanged: 0, recent: 0, old: 0, sampleDates: [] };

  const affected = computers.filter((c) => {
    debugStats.total++;
    if (c.enabled) {
      debugStats.enabled++;
      return false;
    }

    // Use toTimestamp for robust date handling
    const rawWhenChanged = (c as any).whenChanged;
    const whenChangedTime = toTimestamp(rawWhenChanged);

    // Capture sample dates for debugging (first 5 disabled computers)
    if (debugStats.sampleDates.length < 5) {
      debugStats.sampleDates.push({
        name: c.sAMAccountName || 'unknown',
        raw: rawWhenChanged,
        rawType: typeof rawWhenChanged,
        rawStringified: JSON.stringify(rawWhenChanged),
        parsed: whenChangedTime,
        asIso: whenChangedTime ? new Date(whenChangedTime).toISOString() : null,
        whenCreated: (c as any).whenCreated, // Also capture whenCreated for comparison
      });
    }

    if (!whenChangedTime) {
      debugStats.noWhenChanged++;
      return false;
    }

    if (whenChangedTime < thirtyDaysAgo) {
      debugStats.old++;
      return true;
    }
    debugStats.recent++;
    return false;
  });

  return {
    type: 'COMPUTER_DISABLED_NOT_DELETED',
    severity: 'medium',
    category: 'computers',
    title: 'Computer Disabled Not Deleted',
    description: 'Disabled computer not deleted (>30 days). Clutters AD, potential security oversight.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedComputerEntities(affected) : undefined,
    details: {
      debug: debugStats,
      threshold: '30 days',
      checkDate: new Date(thirtyDaysAgo).toISOString(),
      nowDate: new Date(now).toISOString(),
    },
  };
}

/**
 * Check for computer in default Computers container (not organized into OUs)
 *
 * Computers in "CN=Computers,DC=..." are in the default container, not an OU.
 * This indicates they haven't been organized and may not receive proper GPOs.
 *
 * Note: This is different from PingCastle's "Computer_Wrong_OU" which may
 * check for different criteria. We check for computers in default container.
 */
export function detectComputerWrongOu(computers: ADComputer[], includeDetails: boolean): Finding {
  const affected = computers.filter((c) => {
    // Check if computer is directly in the default Computers container
    // DN format: CN=COMPUTER$,CN=Computers,DC=domain,DC=com
    const dnLower = c.dn.toLowerCase();

    // Check if it's in CN=Computers (not OU=)
    // This catches: CN=PC01$,CN=Computers,DC=example,DC=com
    const isInDefaultContainer = dnLower.includes(',cn=computers,dc=');

    return isInDefaultContainer;
  });

  return {
    type: 'COMPUTER_WRONG_OU',
    severity: 'medium',
    category: 'computers',
    title: 'Computer in Default Container',
    description:
      'Computer in default Computers container instead of an organizational OU. ' +
      'May not receive proper Group Policy and indicates lack of organization.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedComputerEntities(affected) : undefined,
  };
}

/**
 * Check for computer with weak encryption (DES/RC4 only)
 */
export function detectComputerWeakEncryption(computers: ADComputer[], includeDetails: boolean): Finding {
  const affected = computers.filter((c) => {
    const encTypes = (c as any)['msDS-SupportedEncryptionTypes'];
    if (typeof encTypes !== 'number') return false;
    // Check if only DES/RC4 (no AES)
    return (encTypes & 0x18) === 0 && (encTypes & 0x7) !== 0;
  });

  return {
    type: 'COMPUTER_WEAK_ENCRYPTION',
    severity: 'medium',
    category: 'computers',
    title: 'Computer Weak Encryption',
    description: 'Computer with weak encryption types (DES/RC4 only). Vulnerable to Kerberos downgrade attacks.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedComputerEntities(affected) : undefined,
  };
}

/**
 * Check for computer description with sensitive data
 */
export function detectComputerDescriptionSensitive(computers: ADComputer[], includeDetails: boolean): Finding {
  const sensitivePatterns = [
    /password|passwd|pwd/i,
    /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/, // IP addresses
    /admin|root|sa/i,
  ];

  const affected = computers.filter((c) => {
    const rawDesc = (c as any).description;
    const description = ldapAttrToString(rawDesc);
    if (!description) return false;
    return sensitivePatterns.some((pattern) => pattern.test(description));
  });

  return {
    type: 'COMPUTER_DESCRIPTION_SENSITIVE',
    severity: 'medium',
    category: 'computers',
    title: 'Computer Description Sensitive',
    description: 'Computer description contains sensitive data (passwords, IPs, etc.). Information disclosure.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedComputerEntities(affected) : undefined,
  };
}

/**
 * Check for Pre-Windows 2000 computer accounts
 */
export function detectComputerPreWindows2000(computers: ADComputer[], includeDetails: boolean): Finding {
  const affected = computers.filter((c) => {
    const os = ldapAttrToString(c.operatingSystem);
    if (!os) return false;
    return /Windows NT|Windows 2000|Windows 95|Windows 98/i.test(os);
  });

  return {
    type: 'COMPUTER_PRE_WINDOWS_2000',
    severity: 'medium',
    category: 'computers',
    title: 'Pre-Windows 2000 Computer',
    description: 'Pre-Windows 2000 compatible computer. Weak security settings, potential compatibility exploits.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedComputerEntities(affected) : undefined,
  };
}

/**
 * Check for computer with adminCount attribute
 */
export function detectComputerAdminCount(computers: ADComputer[], includeDetails: boolean): Finding {
  const affected = computers.filter((c) => {
    const adminCount = (c as any).adminCount;
    return adminCount === 1;
  });

  return {
    type: 'COMPUTER_ADMIN_COUNT',
    severity: 'low',
    category: 'computers',
    title: 'Computer adminCount Set',
    description: 'Computer with adminCount attribute set to 1. May indicate current or former administrative privileges.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedComputerEntities(affected) : undefined,
  };
}

/**
 * Check for computer with SMB signing disabled
 */
export function detectComputerSmbSigningDisabled(computers: ADComputer[], includeDetails: boolean): Finding {
  // Note: This would typically require querying computer configuration
  // For now, we check for an attribute that would be set if SMB signing is disabled
  const affected = computers.filter((c) => {
    return 'smbSigningDisabled' in c && (c as any).smbSigningDisabled;
  });

  return {
    type: 'COMPUTER_SMB_SIGNING_DISABLED',
    severity: 'low',
    category: 'computers',
    title: 'Computer SMB Signing Disabled',
    description: 'Computer with SMB signing disabled. Vulnerable to SMB relay attacks (informational finding).',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedComputerEntities(affected) : undefined,
  };
}

/**
 * Obsolete OS patterns for detection
 */
const OBSOLETE_OS_PATTERNS = [
  {
    pattern: /Windows XP/i,
    type: 'COMPUTER_OS_OBSOLETE_XP',
    severity: 'critical' as const,
    osName: 'Windows XP',
  },
  {
    pattern: /Server 2003/i,
    type: 'COMPUTER_OS_OBSOLETE_2003',
    severity: 'critical' as const,
    osName: 'Windows Server 2003',
  },
  {
    pattern: /Server 2008(?!\s*R2)/i, // 2008 but not 2008 R2
    type: 'COMPUTER_OS_OBSOLETE_2008',
    severity: 'high' as const,
    osName: 'Windows Server 2008',
  },
  {
    pattern: /Windows Vista/i,
    type: 'COMPUTER_OS_OBSOLETE_VISTA',
    severity: 'high' as const,
    osName: 'Windows Vista',
  },
];

/**
 * Check for computers running obsolete operating systems
 * Returns multiple findings, one per OS type detected
 */
export function detectComputerObsoleteOS(
  computers: ADComputer[],
  includeDetails: boolean
): Finding[] {
  return OBSOLETE_OS_PATTERNS.map(({ pattern, type, severity, osName }) => {
    const affected = computers.filter((c) => {
      const os = ldapAttrToString(c.operatingSystem);
      return os && pattern.test(os);
    });

    return {
      type,
      severity,
      category: 'computers' as const,
      title: `Obsolete OS: ${osName}`,
      description: `Computers running ${osName}, an unsupported operating system. No security patches available, making these systems highly vulnerable to exploitation.`,
      count: affected.length,
      affectedEntities: includeDetails ? toAffectedComputerEntities(affected) : undefined,
    };
  }).filter((f) => f.count > 0);
}

/**
 * Check for computers that have never logged on
 * Enabled computers with no lastLogon date may indicate orphaned or unused accounts
 *
 * Checks both lastLogon (local to DC) and lastLogonTimestamp (replicated).
 */
export function detectComputerNeverLoggedOn(
  computers: ADComputer[],
  includeDetails: boolean
): Finding {
  const affected = computers.filter((c) => {
    if (!c.enabled) return false;

    // Check both lastLogon and lastLogonTimestamp
    const lastLogonTime = toTimestamp(c.lastLogon) ?? toTimestamp((c as any)['lastLogonTimestamp']);

    // No logon time means never logged on
    return !lastLogonTime;
  });

  return {
    type: 'COMPUTER_NEVER_LOGGED_ON',
    severity: 'medium',
    category: 'computers',
    title: 'Computer Never Logged On',
    description:
      'Enabled computer accounts that have never authenticated to the domain. These may be orphaned accounts from failed deployments or unused systems that should be cleaned up.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedComputerEntities(affected) : undefined,
  };
}

/**
 * Check for pre-created computer accounts (disabled + never logged on)
 * These are staging accounts that were created but never used.
 * PingCastle: Computer_Pre_Created
 */
export function detectComputerPreCreated(
  computers: ADComputer[],
  includeDetails: boolean
): Finding {
  const affected = computers.filter((c) => {
    // Disabled computer that has never logged on
    if (c.enabled) return false;

    // Check if it has never logged on
    const lastLogonTime = toTimestamp(c.lastLogon) ?? toTimestamp((c as any)['lastLogonTimestamp']);
    return !lastLogonTime;
  });

  return {
    type: 'COMPUTER_PRE_CREATED',
    severity: 'medium',
    category: 'computers',
    title: 'Computer Pre-Created (Staging)',
    description:
      'Disabled computer accounts that have never logged on. These are staging accounts that were created but never deployed. Should be reviewed and cleaned up.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedComputerEntities(affected) : undefined,
  };
}

// ==================== PHASE 2C DETECTORS ====================

/**
 * Detect Domain Controllers not in Domain Controllers OU
 * DCs should always be in the default Domain Controllers OU
 */
export function detectDcNotInDcOu(computers: ADComputer[], includeDetails: boolean): Finding {
  const dcPatterns = [/^DC\d*/i, /domain controller/i];

  const affected = computers.filter((c) => {
    // Check if it's a domain controller
    const dnsName = typeof c.dNSHostName === 'string' ? c.dNSHostName : (Array.isArray(c.dNSHostName) ? c.dNSHostName[0] : '');
    const isDC =
      dcPatterns.some((p) => p.test(c.sAMAccountName || '')) ||
      (dnsName && dnsName.toLowerCase().includes('dc')) ||
      ((c.userAccountControl ?? 0) & 0x2000) !== 0; // SERVER_TRUST_ACCOUNT flag

    if (!isDC) return false;

    // Check if it's in the Domain Controllers OU
    const isInDCOU = c.dn.toLowerCase().includes('ou=domain controllers');

    return !isInDCOU;
  });

  return {
    type: 'DC_NOT_IN_DC_OU',
    severity: 'high',
    category: 'computers',
    title: 'Domain Controller Not in Domain Controllers OU',
    description:
      'Domain Controllers found outside the Domain Controllers OU. This may indicate misconfiguration or an attempt to hide a rogue DC.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedComputerEntities(affected) : undefined,
    details:
      affected.length > 0
        ? {
            recommendation:
              'Move all Domain Controllers to the Domain Controllers OU for proper GPO application and management.',
            risks: [
              'GPOs targeting Domain Controllers OU may not apply',
              'May indicate rogue or compromised DC',
              'Security baselines may not be applied correctly',
            ],
          }
        : undefined,
  };
}

/**
 * Detect duplicate SPNs across computers
 * Duplicate SPNs cause authentication failures
 */
export function detectComputerDuplicateSpn(computers: ADComputer[], includeDetails: boolean): Finding {
  const spnMap = new Map<string, ADComputer[]>();

  // Build SPN to computer mapping
  for (const computer of computers) {
    const spns = computer['servicePrincipalName'];
    if (!spns || !Array.isArray(spns)) continue;

    for (const spn of spns) {
      const normalizedSpn = (spn as string).toLowerCase();
      if (!spnMap.has(normalizedSpn)) {
        spnMap.set(normalizedSpn, []);
      }
      spnMap.get(normalizedSpn)!.push(computer);
    }
  }

  // Find duplicates
  const duplicateComputers = new Set<ADComputer>();
  const duplicateSpns: { spn: string; computers: string[] }[] = [];

  for (const [spn, computersList] of spnMap.entries()) {
    if (computersList.length > 1) {
      duplicateSpns.push({
        spn,
        computers: computersList.map((c) => c.sAMAccountName || c.dn),
      });
      computersList.forEach((c) => duplicateComputers.add(c));
    }
  }

  return {
    type: 'COMPUTER_DUPLICATE_SPN',
    severity: 'medium',
    category: 'computers',
    title: 'Duplicate SPNs Detected',
    description:
      'Multiple computers share the same Service Principal Name. This causes Kerberos authentication failures.',
    count: duplicateComputers.size,
    affectedEntities: includeDetails ? toAffectedComputerEntities(Array.from(duplicateComputers)) : undefined,
    details:
      duplicateSpns.length > 0
        ? {
            duplicateSpns: duplicateSpns.slice(0, 10), // Show first 10
            totalDuplicates: duplicateSpns.length,
            recommendation:
              'Remove duplicate SPNs using setspn -D. Ensure each SPN is unique across the domain.',
          }
        : undefined,
  };
}

/**
 * Detect servers without local admin groups properly configured
 * Servers should have documented local administrators
 */
export function detectServerNoAdminGroup(computers: ADComputer[], includeDetails: boolean): Finding {
  const serverPatterns = [/server/i, /^srv/i, /^sql/i, /^web/i, /^app/i, /^db/i, /^file/i];
  const serverOsPatterns = [/server/i];

  const affected = computers.filter((c) => {
    // Check if it's a server
    const os = ldapAttrToString(c.operatingSystem);
    const isServer =
      serverPatterns.some((p) => p.test(c.sAMAccountName || '')) ||
      (os && serverOsPatterns.some((p) => p.test(os)));

    if (!isServer) return false;

    // Check if it's enabled
    if (!c.enabled) return false;

    // Check if there's a corresponding admin group (naming convention: ServerName-Admins or similar)
    // This is a heuristic - we flag servers that might not have managed admin groups
    // In practice, this would need to be verified against a CMDB or documented standard

    // Flag if it's a server with description indicating it's unmanaged
    const rawDesc = c['description'];
    const description = (typeof rawDesc === 'string' ? rawDesc : (Array.isArray(rawDesc) ? rawDesc[0] : '') || '').toLowerCase();
    const isUnmanaged =
      description.includes('unmanaged') ||
      description.includes('legacy') ||
      description.includes('deprecated');

    return isUnmanaged;
  });

  return {
    type: 'SERVER_NO_ADMIN_GROUP',
    severity: 'medium',
    category: 'computers',
    title: 'Server Without Managed Admin Group',
    description:
      'Servers identified as unmanaged or without proper administrative group documentation. Local admin access may not be properly controlled.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedComputerEntities(affected) : undefined,
    details:
      affected.length > 0
        ? {
            recommendation:
              'Create dedicated admin groups for each server (e.g., SRV01-Admins) and document access.',
            risks: [
              'Unknown administrators may have access',
              'Audit trail for admin actions may be incomplete',
              'Compliance violations for access management',
            ],
          }
        : undefined,
  };
}

/**
 * Detect workstations in server OUs
 * Workstations should be in workstation OUs, not server OUs
 */
export function detectWorkstationInServerOu(computers: ADComputer[], includeDetails: boolean): Finding {
  const serverOuPatterns = [/ou=servers/i, /ou=server/i, /ou=datacenter/i, /ou=production/i];
  const workstationOsPatterns = [/windows 10/i, /windows 11/i, /windows 7/i, /windows 8/i];
  const workstationNamePatterns = [/^ws/i, /^pc/i, /^laptop/i, /^desktop/i, /^nb/i];

  const affected = computers.filter((c) => {
    // Check if it's in a server OU
    const isInServerOU = serverOuPatterns.some((p) => p.test(c.dn));
    if (!isInServerOU) return false;

    // Check if it's actually a workstation (not a server)
    const os = ldapAttrToString(c.operatingSystem);
    const isWorkstation =
      workstationNamePatterns.some((p) => p.test(c.sAMAccountName || '')) ||
      (os && workstationOsPatterns.some((p) => p.test(os)));

    return isWorkstation;
  });

  return {
    type: 'WORKSTATION_IN_SERVER_OU',
    severity: 'low',
    category: 'computers',
    title: 'Workstation in Server OU',
    description:
      'Workstation computers found in server OUs. This causes incorrect GPO application and may indicate organizational issues.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedComputerEntities(affected) : undefined,
    details:
      affected.length > 0
        ? {
            recommendation: 'Move workstations to appropriate workstation OUs for proper GPO targeting.',
            impact: 'Server-targeted GPOs may apply to workstations causing configuration issues.',
          }
        : undefined,
  };
}

/**
 * Detect computers without BitLocker encryption
 *
 * Computers without disk encryption are vulnerable to physical attacks
 * where hard drives can be removed and read.
 *
 * @param computers - Array of AD computers
 * @param includeDetails - Whether to include affected entity details
 * @returns Finding for COMPUTER_NO_BITLOCKER
 */
export function detectComputerNoBitlocker(
  computers: ADComputer[],
  includeDetails: boolean
): Finding {
  // BitLocker status is stored in ms-FVE-RecoveryInformation objects under the computer
  // We can check for msDS-isGC or look for recovery info attributes
  // For now, we check servers (not workstations) that likely need encryption
  const serversWithoutBitlocker = computers.filter((c) => {
    if (!c.enabled) return false;
    const os = ldapAttrToString(c.operatingSystem).toLowerCase();
    const isServer = os.includes('server');
    // Check if BitLocker recovery info exists (would need separate query)
    // For now, flag servers that might need BitLocker review
    const hasBitlockerInfo = (c as Record<string, unknown>)['ms-FVE-RecoveryInformation'] !== undefined;
    return isServer && !hasBitlockerInfo;
  });

  return {
    type: 'COMPUTER_NO_BITLOCKER',
    severity: 'high',
    category: 'computers',
    title: 'BitLocker Not Detected',
    description:
      'Servers without BitLocker recovery information in AD. ' +
      'Unencrypted disks are vulnerable to physical theft and offline attacks.',
    count: serversWithoutBitlocker.length,
    affectedEntities: includeDetails
      ? toAffectedComputerEntities(serversWithoutBitlocker)
      : undefined,
    details: {
      recommendation:
        'Enable BitLocker on all servers and configure AD backup of recovery keys.',
      note: 'This detection checks for ms-FVE-RecoveryInformation in AD. Standalone BitLocker may not be detected.',
    },
  };
}

/**
 * Detect computers using legacy protocols
 *
 * Computers configured to use legacy/insecure protocols like SMBv1,
 * NTLMv1, or LM are vulnerable to various attacks.
 *
 * @param computers - Array of AD computers
 * @param includeDetails - Whether to include affected entity details
 * @returns Finding for COMPUTER_LEGACY_PROTOCOL
 */
export function detectComputerLegacyProtocol(
  computers: ADComputer[],
  includeDetails: boolean
): Finding {
  // Check for computers with legacy OS that likely use legacy protocols
  const legacyOsPatterns = [
    /Windows XP/i,
    /Windows 2000/i,
    /Windows NT/i,
    /Server 2003/i,
    /Windows Vista/i,
  ];

  // Also check msDS-SupportedEncryptionTypes for weak encryption
  const affected = computers.filter((c) => {
    if (!c.enabled) return false;
    const os = ldapAttrToString(c.operatingSystem);

    // Legacy OS definitely uses legacy protocols
    const hasLegacyOs = legacyOsPatterns.some((p) => p.test(os));
    if (hasLegacyOs) return true;

    // Check supported encryption types (if only DES/RC4)
    const encTypes = (c as Record<string, unknown>)['msDS-SupportedEncryptionTypes'] as number | undefined;
    if (encTypes !== undefined) {
      // If only DES (0x1, 0x2) or RC4 (0x4) are supported, it's legacy
      const onlyLegacy = (encTypes & 0x18) === 0; // No AES128 (0x8) or AES256 (0x10)
      if (onlyLegacy && encTypes > 0) return true;
    }

    return false;
  });

  return {
    type: 'COMPUTER_LEGACY_PROTOCOL',
    severity: 'medium',
    category: 'computers',
    title: 'Legacy Protocol Support',
    description:
      'Computers configured to use legacy protocols (SMBv1, NTLMv1, DES/RC4 only). ' +
      'These are vulnerable to relay attacks, credential theft, and encryption downgrade.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedComputerEntities(affected) : undefined,
    details: {
      recommendation:
        'Upgrade legacy systems or disable legacy protocols. Enable AES encryption support.',
      protocols: ['SMBv1', 'NTLMv1', 'DES', 'RC4'],
    },
  };
}

/**
 * Detect all computer-related vulnerabilities
 */
export function detectComputersVulnerabilities(
  computers: ADComputer[],
  includeDetails: boolean
): Finding[] {
  // Get obsolete OS findings (returns array)
  const obsoleteOsFindings = detectComputerObsoleteOS(computers, includeDetails);

  return [
    ...obsoleteOsFindings,
    detectComputerNeverLoggedOn(computers, includeDetails),
    detectComputerPreCreated(computers, includeDetails),
    detectComputerConstrainedDelegation(computers, includeDetails),
    detectComputerRbcd(computers, includeDetails),
    detectComputerInAdminGroup(computers, includeDetails),
    detectComputerDcsyncRights(computers, includeDetails),
    detectComputerUnconstrainedDelegation(computers, includeDetails),
    detectComputerStaleInactive(computers, includeDetails),
    detectComputerPasswordOld(computers, includeDetails),
    detectComputerWithSpns(computers, includeDetails),
    detectComputerNoLaps(computers, includeDetails),
    detectComputerAclAbuse(computers, includeDetails),
    detectComputerDisabledNotDeleted(computers, includeDetails),
    detectComputerWrongOu(computers, includeDetails),
    detectComputerWeakEncryption(computers, includeDetails),
    detectComputerDescriptionSensitive(computers, includeDetails),
    detectComputerPreWindows2000(computers, includeDetails),
    detectComputerAdminCount(computers, includeDetails),
    detectComputerSmbSigningDisabled(computers, includeDetails),
    // Phase 2C: Enhanced detections
    detectDcNotInDcOu(computers, includeDetails),
    detectComputerDuplicateSpn(computers, includeDetails),
    detectServerNoAdminGroup(computers, includeDetails),
    detectWorkstationInServerOu(computers, includeDetails),
    // Phase 4: Advanced detections
    detectComputerNoBitlocker(computers, includeDetails),
    detectComputerLegacyProtocol(computers, includeDetails),
  ].filter((finding) => {
    // Include findings with count > 0
    if (finding.count > 0) return true;
    // Also include findings with debug details (for troubleshooting)
    if (finding.details?.['debug']) return true;
    return false;
  });
}
