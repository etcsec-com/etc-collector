/**
 * Entity Converter Utilities
 *
 * Converts AD and Azure AD objects to enriched entity format for findings
 */

import { ADUser, ADGroup, ADComputer } from '../types/ad.types';
import { AzureUser, AzureApp, AzureGroup } from '../types/azure.types';
import {
  AffectedUserEntity,
  AffectedAzureUserEntity,
  AffectedAppEntity,
  AffectedGroupEntity,
  AffectedComputerEntity,
} from '../types/finding.types';

/**
 * Windows FILETIME epoch offset (100-nanosecond intervals from 1601 to 1970)
 */
const FILETIME_EPOCH_OFFSET = 11644473600000;

/**
 * Safely convert LDAP attribute to string
 * LDAP attributes can be strings, arrays, or undefined
 */
export function ldapAttrToString(value: unknown): string {
  if (typeof value === 'string') return value;
  if (Array.isArray(value) && value.length > 0) return String(value[0]);
  if (value === null || value === undefined) return '';
  return String(value);
}

/**
 * Convert Windows FILETIME to ISO 8601 string
 * FILETIME is 100-nanosecond intervals since January 1, 1601 UTC
 */
function filetimeToIso(filetime: string | number | undefined | null): string | null {
  if (!filetime) return null;

  let filetimeNum: number;
  if (typeof filetime === 'string') {
    filetimeNum = parseInt(filetime, 10);
  } else {
    filetimeNum = filetime;
  }

  // Check for invalid values (0 or max value means "never" or "not set")
  if (filetimeNum === 0 || filetimeNum >= 9223372036854775807) {
    return null;
  }

  // Convert from 100-nanosecond intervals to milliseconds
  const milliseconds = filetimeNum / 10000;

  // Subtract Windows epoch offset
  const unixTimestamp = milliseconds - FILETIME_EPOCH_OFFSET;

  // Validate timestamp is reasonable
  if (unixTimestamp < 0 || unixTimestamp > Date.now() + 100 * 365 * 24 * 60 * 60 * 1000) {
    return null;
  }

  return new Date(unixTimestamp).toISOString();
}

/**
 * Convert Date object to ISO 8601 string
 */
function dateToIso(date: Date | string | undefined | null): string | null {
  if (!date) return null;

  if (date instanceof Date) {
    return date.toISOString();
  }

  // If it's already a string (e.g., LDAP generalized time format)
  if (typeof date === 'string') {
    // Check if it's already ISO format
    if (date.includes('T') || date.includes('Z')) {
      return date;
    }

    // LDAP generalized time format: 20230615080000.0Z
    const match = date.match(/^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})/);
    if (match && match[1] && match[2] && match[3] && match[4] && match[5] && match[6]) {
      return new Date(
        Date.UTC(
          parseInt(match[1]),
          parseInt(match[2]) - 1,
          parseInt(match[3]),
          parseInt(match[4]),
          parseInt(match[5]),
          parseInt(match[6])
        )
      ).toISOString();
    }
  }

  return null;
}

/**
 * Get string value or null
 */
function strOrNull(value: unknown): string | null {
  if (value === undefined || value === null || value === '') return null;
  return String(value);
}

/**
 * Get number value or default
 */
function numOrDefault(value: unknown, defaultVal: number): number {
  if (value === undefined || value === null) return defaultVal;
  const num = typeof value === 'number' ? value : parseInt(String(value), 10);
  return isNaN(num) ? defaultVal : num;
}

/**
 * Get array of strings from value
 */
function toStringArray(value: unknown): string[] {
  if (!value) return [];
  if (Array.isArray(value)) return value.map(String);
  return [String(value)];
}

/**
 * Convert ADUser to AffectedUserEntity with all attributes
 */
export function toAffectedUserEntity(user: ADUser): AffectedUserEntity {
  // Determine enabled status from userAccountControl (flag 0x2 = ACCOUNTDISABLE)
  const uac = user.userAccountControl ?? 0;
  const enabled = (uac & 0x2) === 0;

  return {
    // Type discriminator
    type: 'user',

    // Identity (5)
    dn: user.dn,
    sAMAccountName: user.sAMAccountName,
    userPrincipalName: strOrNull(user.userPrincipalName),
    displayName: strOrNull(user.displayName),
    mail: strOrNull(user.mail),

    // Organization (8)
    title: strOrNull(user.title),
    department: strOrNull(user.department),
    company: strOrNull(user.company),
    manager: strOrNull(user.manager),
    physicalDeliveryOfficeName: strOrNull(user.physicalDeliveryOfficeName),
    description: strOrNull(user.description),
    employeeID: strOrNull(user.employeeID),
    telephoneNumber: strOrNull(user.telephoneNumber),

    // Dates (5) - convert to ISO 8601
    whenCreated: dateToIso(user.whenCreated),
    whenChanged: dateToIso(user.whenChanged),
    lastLogon: user.lastLogon ? user.lastLogon.toISOString() : filetimeToIso((user as any)['lastLogon']),
    pwdLastSet: user.passwordLastSet
      ? user.passwordLastSet.toISOString()
      : filetimeToIso(user.pwdLastSet),
    accountExpires: filetimeToIso(user.accountExpires),

    // Security (5)
    badPwdCount: numOrDefault(user.badPwdCount, 0),
    lockoutTime: filetimeToIso(user.lockoutTime),
    adminCount: numOrDefault(user.adminCount, 0),
    memberOf: toStringArray(user.memberOf),
    enabled,
  };
}

/**
 * Convert array of ADUsers to AffectedUserEntity array
 */
export function toAffectedUserEntities(users: ADUser[]): AffectedUserEntity[] {
  return users.map(toAffectedUserEntity);
}

// ==================== AZURE AD CONVERTERS ====================

/**
 * Extract manager display name or ID from Azure user manager property
 */
function getAzureManagerStr(manager: AzureUser['manager']): string | null {
  if (!manager) return null;
  if (typeof manager === 'string') return manager;
  if (typeof manager === 'object') {
    return manager.displayName || manager.id || null;
  }
  return null;
}

/**
 * Extract assigned license SKU IDs as array of strings
 */
function getAzureLicenses(licenses: AzureUser['assignedLicenses']): string[] {
  if (!licenses || !Array.isArray(licenses)) return [];
  return licenses.map((l) => l.skuId || 'unknown').filter(Boolean);
}

/**
 * Extract group/role memberships as array of strings
 */
function getAzureMemberOf(memberOf: AzureUser['memberOf']): string[] {
  if (!memberOf || !Array.isArray(memberOf)) return [];
  return memberOf.map((m) => {
    if (typeof m === 'string') return m;
    if (typeof m === 'object' && m) {
      return m.displayName || m.id || '';
    }
    return '';
  }).filter(Boolean);
}

/**
 * Convert AzureUser to AffectedAzureUserEntity with all attributes
 */
export function toAffectedAzureUserEntity(user: AzureUser): AffectedAzureUserEntity {
  return {
    // Type discriminator
    type: 'azureUser',

    // Identity (6)
    id: user.id,
    userPrincipalName: user.userPrincipalName,
    displayName: strOrNull(user.displayName),
    mail: strOrNull(user.mail),
    givenName: strOrNull(user.givenName),
    surname: strOrNull(user.surname),

    // Organization (6)
    jobTitle: strOrNull(user.jobTitle),
    department: strOrNull(user.department),
    companyName: strOrNull(user.companyName),
    manager: getAzureManagerStr(user.manager),
    officeLocation: strOrNull(user.officeLocation),
    employeeId: strOrNull(user.employeeId),

    // Dates (3) - Azure dates are already ISO 8601
    createdDateTime: strOrNull(user.createdDateTime),
    lastSignInDateTime: strOrNull(user.lastSignInDateTime),
    lastPasswordChangeDateTime: strOrNull(user.lastPasswordChangeDateTime),

    // Security (7)
    accountEnabled: user.accountEnabled,
    userType: strOrNull(user.userType),
    riskLevel: strOrNull(user.riskLevel),
    riskState: strOrNull(user.riskState),
    isMfaRegistered: user.isMfaRegistered === true || (user.strongAuthenticationMethods?.length ?? 0) > 0,
    assignedLicenses: getAzureLicenses(user.assignedLicenses),
    memberOf: getAzureMemberOf(user.memberOf),
  };
}

/**
 * Convert array of AzureUsers to AffectedAzureUserEntity array
 */
export function toAffectedAzureUserEntities(users: AzureUser[]): AffectedAzureUserEntity[] {
  return users.map(toAffectedAzureUserEntity);
}

// ==================== AZURE APP CONVERTERS ====================

/**
 * Get oldest credential expiry date from app credentials
 */
function getOldestCredentialExpiry(app: AzureApp): string | null {
  const credentials = [
    ...((app as any).passwordCredentials || []),
    ...((app as any).keyCredentials || []),
  ];

  if (credentials.length === 0) return null;

  const expiries = credentials
    .map((c: any) => c.endDateTime as string | undefined)
    .filter((d): d is string => Boolean(d))
    .map((d) => new Date(d).getTime())
    .sort((a, b) => a - b);

  return expiries.length > 0 ? new Date(expiries[0]!).toISOString() : null;
}

/**
 * Convert AzureApp to AffectedAppEntity
 */
export function toAffectedAppEntity(app: AzureApp): AffectedAppEntity {
  const passwordCreds = (app as any).passwordCredentials || [];
  const keyCreds = (app as any).keyCredentials || [];

  return {
    id: app.id,
    displayName: app.displayName,
    type: 'application',

    // App details
    appId: strOrNull(app.appId),
    signInAudience: strOrNull(app.signInAudience),
    createdDateTime: strOrNull(app.createdDateTime),

    // Security
    publisherDomain: strOrNull((app as any).publisherDomain),
    verifiedPublisher: !!(app as any).verifiedPublisher?.displayName,
    credentialCount: passwordCreds.length + keyCreds.length,
    oldestCredentialExpiry: getOldestCredentialExpiry(app),
  };
}

/**
 * Convert array of AzureApps to AffectedAppEntity array
 */
export function toAffectedAppEntities(apps: AzureApp[]): AffectedAppEntity[] {
  return apps.map(toAffectedAppEntity);
}

// ==================== GROUP CONVERTERS ====================

/**
 * Get AD group type from groupType attribute
 */
function getADGroupType(groupType: number | undefined): string | null {
  if (groupType === undefined) return null;
  // Bit 0x80000000 = Security group, otherwise Distribution
  return (groupType & 0x80000000) !== 0 ? 'Security' : 'Distribution';
}

/**
 * Get AD group scope from groupType attribute
 */
function getADGroupScope(groupType: number | undefined): string | null {
  if (groupType === undefined) return null;
  // Bits: 0x2 = Global, 0x4 = DomainLocal, 0x8 = Universal
  if ((groupType & 0x8) !== 0) return 'Universal';
  if ((groupType & 0x4) !== 0) return 'DomainLocal';
  if ((groupType & 0x2) !== 0) return 'Global';
  return null;
}

/**
 * Convert ADGroup to AffectedGroupEntity
 */
export function toAffectedADGroupEntity(group: ADGroup): AffectedGroupEntity {
  const groupTypeNum = group.groupType;

  return {
    id: group.dn,
    displayName: group.cn || group.displayName || group.sAMAccountName || group.dn,
    type: 'group',

    // AD-specific
    sAMAccountName: strOrNull(group.sAMAccountName),
    groupType: getADGroupType(groupTypeNum),
    groupScope: getADGroupScope(groupTypeNum),

    // Azure-specific (null for AD)
    securityEnabled: null,
    mailEnabled: null,
    groupTypes: [],

    // Common
    memberCount: Array.isArray(group.member) ? group.member.length : null,
    description: strOrNull(group.description),
  };
}

/**
 * Convert array of ADGroups to AffectedGroupEntity array
 */
export function toAffectedADGroupEntities(groups: ADGroup[]): AffectedGroupEntity[] {
  return groups.map(toAffectedADGroupEntity);
}

/**
 * Convert AzureGroup to AffectedGroupEntity
 */
export function toAffectedAzureGroupEntity(group: AzureGroup): AffectedGroupEntity {
  return {
    id: group.id,
    displayName: group.displayName,
    type: 'group',

    // AD-specific (null for Azure)
    sAMAccountName: null,
    groupType: null,
    groupScope: null,

    // Azure-specific
    securityEnabled: group.securityEnabled ?? null,
    mailEnabled: group.mailEnabled ?? null,
    groupTypes: group.groupTypes || [],

    // Common
    memberCount: (group as any).memberCount ?? null,
    description: strOrNull((group as any).description),
  };
}

/**
 * Convert array of AzureGroups to AffectedGroupEntity array
 */
export function toAffectedAzureGroupEntities(groups: AzureGroup[]): AffectedGroupEntity[] {
  return groups.map(toAffectedAzureGroupEntity);
}

// ==================== COMPUTER CONVERTERS ====================

/**
 * Convert ADComputer to AffectedComputerEntity
 */
export function toAffectedComputerEntity(computer: ADComputer): AffectedComputerEntity {
  const uac = computer.userAccountControl ?? 0;
  const enabled = (uac & 0x2) === 0; // ACCOUNTDISABLE flag

  return {
    id: computer.dn,
    displayName: computer.cn || computer.sAMAccountName || computer.dn,
    type: 'computer',

    // Identity
    sAMAccountName: computer.sAMAccountName,
    dNSHostName: strOrNull(computer.dNSHostName),

    // OS Info
    operatingSystem: strOrNull(computer.operatingSystem),
    operatingSystemVersion: strOrNull(computer.operatingSystemVersion),

    // Dates
    whenCreated: dateToIso(computer.whenCreated),
    lastLogon: computer.lastLogon
      ? computer.lastLogon.toISOString()
      : filetimeToIso((computer as any)['lastLogonTimestamp']),
    pwdLastSet: computer.passwordLastSet
      ? computer.passwordLastSet.toISOString()
      : filetimeToIso((computer as any)['pwdLastSet']),

    // Security
    enabled,
    userAccountControl: uac,

    // Dates for debugging
    whenChanged: dateToIso((computer as any).whenChanged),
  };
}

/**
 * Convert array of ADComputers to AffectedComputerEntity array
 */
export function toAffectedComputerEntities(computers: ADComputer[]): AffectedComputerEntity[] {
  return computers.map(toAffectedComputerEntity);
}
