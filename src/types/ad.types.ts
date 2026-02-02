/**
 * Active Directory Types
 */

export interface ADUser {
  // Core identity
  dn: string;
  sAMAccountName: string;
  userPrincipalName?: string;
  displayName?: string;
  mail?: string;

  // Organization
  title?: string;
  department?: string;
  company?: string;
  manager?: string;
  physicalDeliveryOfficeName?: string;
  description?: string;
  employeeID?: string;
  telephoneNumber?: string;

  // Dates (raw from LDAP, may need conversion)
  whenCreated?: string | Date;
  whenChanged?: string | Date;
  lastLogon?: Date;
  passwordLastSet?: Date;
  pwdLastSet?: string | number; // Raw FILETIME
  accountExpires?: string | number; // Raw FILETIME

  // Security
  badPwdCount?: number;
  lockoutTime?: string | number; // Raw FILETIME
  adminCount?: number;
  memberOf?: string[];
  userAccountControl?: number;
  enabled: boolean;

  // Allow additional attributes
  [key: string]: unknown;
}

export interface ADGroup {
  dn: string;
  sAMAccountName: string;
  cn?: string;
  displayName?: string;
  description?: string;
  groupType?: number;
  memberOf?: string[];
  member?: string[];
  [key: string]: unknown;
}

export interface ADComputer {
  dn: string;
  sAMAccountName: string;
  cn?: string;
  dNSHostName?: string;
  operatingSystem?: string;
  operatingSystemVersion?: string;
  whenCreated?: string | Date;
  lastLogon?: Date;
  passwordLastSet?: Date;
  userAccountControl?: number;
  enabled: boolean;
  [key: string]: unknown;
}

export interface ADOU {
  dn: string;
  name: string;
  description?: string;
  [key: string]: unknown;
}

export interface ADDomain {
  dn: string;
  name: string;
  domainFunctionalLevel?: number;
  forestFunctionalLevel?: number;
  [key: string]: unknown;
}

export interface AclEntry {
  objectDn: string;
  trustee: string;
  accessMask: number;
  aceType: string;
  objectType?: string;
}
