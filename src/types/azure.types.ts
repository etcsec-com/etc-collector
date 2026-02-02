/**
 * Azure AD Types
 */

export interface AzureUser {
  // Core identity
  id: string;
  userPrincipalName: string;
  displayName?: string;
  mail?: string;
  givenName?: string;
  surname?: string;

  // Organization
  jobTitle?: string;
  department?: string;
  companyName?: string;
  manager?: { id?: string; displayName?: string } | string;
  officeLocation?: string;
  employeeId?: string;

  // Dates
  createdDateTime?: string;
  lastSignInDateTime?: string;
  lastPasswordChangeDateTime?: string;

  // Security
  accountEnabled: boolean;
  userType?: string; // "Member" | "Guest"
  riskLevel?: string;
  riskState?: string;
  isMfaRegistered?: boolean;
  strongAuthenticationMethods?: unknown[];
  assignedLicenses?: Array<{ skuId?: string }>;
  memberOf?: Array<{ id?: string; displayName?: string }> | string[];
  passwordPolicies?: string;

  // Allow additional attributes
  [key: string]: unknown;
}

export interface AzureGroup {
  id: string;
  displayName: string;
  mailEnabled: boolean;
  securityEnabled: boolean;
  groupTypes?: string[];
  members?: string[];
  [key: string]: unknown;
}

export interface AzureApp {
  id: string;
  appId: string;
  displayName: string;
  createdDateTime?: string;
  signInAudience?: string;
  [key: string]: unknown;
}

export interface AzurePolicy {
  id: string;
  displayName: string;
  state?: string;
  conditions?: unknown;
  grantControls?: unknown;
  [key: string]: unknown;
}
