import { Entry } from 'ldapts';
import { ADUser, ADGroup, ADComputer, ADOU } from '../../types/ad.types';
import { logger } from '../../utils/logger';

/**
 * Active Directory Type Mappers
 *
 * Maps raw LDAP entries to typed AD objects.
 * Handles AD-specific attributes and data type conversions.
 *
 * Task 4: Create AD Type Mappers (Story 1.5)
 */

/**
 * Convert Windows FILETIME to JavaScript Date
 *
 * Windows FILETIME is 100-nanosecond intervals since Jan 1, 1601 UTC.
 * JavaScript Date uses milliseconds since Jan 1, 1970 UTC.
 *
 * @param filetime - FILETIME value as string
 * @returns Date object or undefined if invalid
 */
function fileTimeToDate(filetime: string | undefined): Date | undefined {
  if (!filetime) {
    return undefined;
  }

  try {
    const value = BigInt(filetime);

    // Special values in AD
    if (value === BigInt(0) || value === BigInt('9223372036854775807')) {
      // 0 or max value means "never" or "not set"
      return undefined;
    }

    // Convert Windows FILETIME to Unix timestamp
    // 116444736000000000 = 100-ns intervals between 1601 and 1970
    const unixTimestamp = Number((value - BigInt('116444736000000000')) / BigInt(10000));

    return new Date(unixTimestamp);
  } catch (error) {
    logger.warn(`Failed to convert FILETIME: ${filetime}`, error);
    return undefined;
  }
}

/**
 * Get string value from LDAP attribute
 *
 * LDAP attributes can be strings, arrays, or Buffer objects.
 *
 * @param value - LDAP attribute value
 * @returns String value or undefined
 */
function getString(value: unknown): string | undefined {
  if (!value) {
    return undefined;
  }

  if (typeof value === 'string') {
    return value;
  }

  if (Array.isArray(value)) {
    return value[0]?.toString();
  }

  if (Buffer.isBuffer(value)) {
    return value.toString('utf-8');
  }

  return String(value);
}

/**
 * Get string array from LDAP attribute
 *
 * @param value - LDAP attribute value
 * @returns Array of strings or undefined
 */
function getStringArray(value: unknown): string[] | undefined {
  if (!value) {
    return undefined;
  }

  if (Array.isArray(value)) {
    return value.map((v) => (Buffer.isBuffer(v) ? v.toString('utf-8') : String(v)));
  }

  // Single value
  return [getString(value)!].filter(Boolean);
}

/**
 * Get number from LDAP attribute
 *
 * @param value - LDAP attribute value
 * @returns Number or undefined
 */
function getNumber(value: unknown): number | undefined {
  if (!value) {
    return undefined;
  }

  const str = getString(value);
  if (!str) {
    return undefined;
  }

  const num = parseInt(str, 10);
  return isNaN(num) ? undefined : num;
}

/**
 * Check if AD account is enabled
 *
 * Uses userAccountControl attribute bit flags.
 * Bit 1 (0x0002) = ACCOUNTDISABLE
 *
 * @param userAccountControl - userAccountControl value
 * @returns true if enabled, false if disabled
 */
function isAccountEnabled(userAccountControl: number | undefined): boolean {
  if (userAccountControl === undefined) {
    return true; // Default to enabled if not specified
  }

  const ACCOUNTDISABLE = 0x0002;
  return (userAccountControl & ACCOUNTDISABLE) === 0;
}

/**
 * Map LDAP entry to ADUser
 *
 * @param entry - LDAP search entry
 * @returns ADUser object
 */
export function mapToADUser(entry: Entry): ADUser {
  const userAccountControl = getNumber(entry['userAccountControl']);

  const user: ADUser = {
    dn: entry.dn,
    sAMAccountName: getString(entry['sAMAccountName']) || '',
    userPrincipalName: getString(entry['userPrincipalName']),
    displayName: getString(entry['displayName']),
    enabled: isAccountEnabled(userAccountControl),
    passwordLastSet: fileTimeToDate(getString(entry['pwdLastSet'])),
    lastLogon: fileTimeToDate(getString(entry['lastLogon'])),
    adminCount: getNumber(entry['adminCount']),
    memberOf: getStringArray(entry['memberOf']),
    userAccountControl,
  };

  // Include all other attributes
  for (const [key, value] of Object.entries(entry)) {
    if (!(key in user)) {
      user[key] = value;
    }
  }

  return user;
}

/**
 * Map LDAP entry to ADGroup
 *
 * @param entry - LDAP search entry
 * @returns ADGroup object
 */
export function mapToADGroup(entry: Entry): ADGroup {
  const group: ADGroup = {
    dn: entry.dn,
    sAMAccountName: getString(entry['sAMAccountName']) || '',
    displayName: getString(entry['displayName']),
    groupType: getNumber(entry['groupType']),
    memberOf: getStringArray(entry['memberOf']),
    member: getStringArray(entry['member']),
  };

  // Include all other attributes
  for (const [key, value] of Object.entries(entry)) {
    if (!(key in group)) {
      group[key] = value;
    }
  }

  return group;
}

/**
 * Map LDAP entry to ADComputer
 *
 * @param entry - LDAP search entry
 * @returns ADComputer object
 */
export function mapToADComputer(entry: Entry): ADComputer {
  const userAccountControl = getNumber(entry['userAccountControl']);

  const computer: ADComputer = {
    dn: entry.dn,
    sAMAccountName: getString(entry['sAMAccountName']) || '',
    dNSHostName: getString(entry['dNSHostName']),
    operatingSystem: getString(entry['operatingSystem']),
    operatingSystemVersion: getString(entry['operatingSystemVersion']),
    lastLogon: fileTimeToDate(getString(entry['lastLogon'])),
    enabled: isAccountEnabled(userAccountControl),
  };

  // Include all other attributes
  for (const [key, value] of Object.entries(entry)) {
    if (!(key in computer)) {
      computer[key] = value;
    }
  }

  return computer;
}

/**
 * Map LDAP entry to ADOU
 *
 * @param entry - LDAP search entry
 * @returns ADOU object
 */
export function mapToADOU(entry: Entry): ADOU {
  const ou: ADOU = {
    dn: entry.dn,
    name: getString(entry['name']) || getString(entry['ou']) || '',
    description: getString(entry['description']),
  };

  // Include all other attributes
  for (const [key, value] of Object.entries(entry)) {
    if (!(key in ou)) {
      ou[key] = value;
    }
  }

  return ou;
}

/**
 * Generic mapper for custom types
 *
 * Maps LDAP entry to a plain object with all attributes.
 *
 * @param entry - LDAP search entry
 * @returns Plain object with all entry attributes
 */
export function mapToGeneric(entry: Entry): Record<string, unknown> {
  const result: Record<string, unknown> = {
    dn: entry.dn,
  };

  // Binary attributes that should NOT be converted to strings
  const binaryAttributes = new Set(['nTSecurityDescriptor', 'objectGUID', 'objectSid']);

  // Include all attributes
  for (const [key, value] of Object.entries(entry)) {
    if (key === 'dn') continue; // Already added

    // Preserve binary attributes as Buffers
    if (binaryAttributes.has(key) && Buffer.isBuffer(value)) {
      result[key] = value;
    }
    // Try to convert to proper types
    else if (typeof value === 'string' && /^\d+$/.test(value)) {
      result[key] = parseInt(value, 10);
    } else if (Array.isArray(value)) {
      result[key] = value.map((v) => (Buffer.isBuffer(v) ? v.toString('utf-8') : v));
    } else if (Buffer.isBuffer(value)) {
      result[key] = value.toString('utf-8');
    } else {
      result[key] = value;
    }
  }

  return result;
}
