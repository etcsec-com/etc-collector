/**
 * User Security Vulnerability Detector for Azure AD
 *
 * Detects user-related vulnerabilities in Azure AD/Entra ID.
 * Story 1.8: Azure Vulnerability Detection Engine
 *
 * Vulnerabilities detected (10):
 * CRITICAL (3):
 * - AZURE_GLOBAL_ADMIN_NO_MFA
 * - AZURE_PRIVILEGED_USER_NO_MFA
 * - AZURE_RISKY_USER_HIGH
 *
 * HIGH (3):
 * - AZURE_USER_INACTIVE
 * - AZURE_USER_PASSWORD_NEVER_EXPIRES
 * - AZURE_RISKY_USER_MEDIUM
 *
 * MEDIUM (4):
 * - AZURE_PASSWORD_OLD
 * - AZURE_USER_NEVER_SIGNED_IN
 * - AZURE_USER_UNLICENSED
 * - AZURE_USER_EXTERNAL_MEMBER
 */

import { AzureUser } from '../../../../types/azure.types';
import { Finding } from '../../../../types/finding.types';
import { toAffectedAzureUserEntities } from '../../../../utils/entity-converter';

/**
 * Check for Global Administrators without MFA
 */
export function detectGlobalAdminNoMfa(
  users: AzureUser[],
  roles: Map<string, string[]>,
  includeDetails: boolean
): Finding {
  const globalAdminRoleId = '62e90394-69f5-4237-9190-012177145e10'; // Well-known Global Admin role ID

  const affected = users.filter((u) => {
    const userRoles = roles.get(u.id) || [];
    const isGlobalAdmin = userRoles.includes(globalAdminRoleId);
    const hasMfa = (u as any).strongAuthenticationMethods?.length > 0 || (u as any).isMfaRegistered === true;

    return isGlobalAdmin && !hasMfa;
  });

  return {
    type: 'AZURE_GLOBAL_ADMIN_NO_MFA',
    severity: 'critical',
    category: 'identity',
    title: 'Global Administrator without MFA',
    description: 'Global Administrator account without Multi-Factor Authentication. Full control over Azure AD if compromised.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedAzureUserEntities(affected) : undefined,
  };
}

/**
 * Check for privileged users (non-GA) without MFA
 */
export function detectPrivilegedUserNoMfa(
  users: AzureUser[],
  roles: Map<string, string[]>,
  includeDetails: boolean
): Finding {
  const privilegedRoleIds = [
    '62e90394-69f5-4237-9190-012177145e10', // Global Administrator
    'e8611ab8-c189-46e8-94e1-60213ab1f814', // Privileged Role Administrator
    '194ae4cb-b126-40b2-bd5b-6091b380977d', // Security Administrator
    '29232cdf-9323-42fd-ade2-1d097af3e4de', // Exchange Administrator
    'f28a1f50-f6e7-4571-818b-6a12f2af6b6c', // SharePoint Administrator
  ];

  const affected = users.filter((u) => {
    const userRoles = roles.get(u.id) || [];
    const hasPrivilegedRole = userRoles.some((r) => privilegedRoleIds.includes(r));
    const hasMfa = (u as any).strongAuthenticationMethods?.length > 0 || (u as any).isMfaRegistered === true;

    return hasPrivilegedRole && !hasMfa;
  });

  return {
    type: 'AZURE_PRIVILEGED_USER_NO_MFA',
    severity: 'critical',
    category: 'identity',
    title: 'Privileged User without MFA',
    description: 'Privileged role assigned to user without MFA. High risk if account is compromised.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedAzureUserEntities(affected) : undefined,
  };
}

/**
 * Check for high-risk users (Identity Protection)
 */
export function detectRiskyUserHigh(users: AzureUser[], includeDetails: boolean): Finding {
  const affected = users.filter((u) => {
    const riskLevel = (u as any).riskLevel;
    return riskLevel === 'high';
  });

  return {
    type: 'AZURE_RISKY_USER_HIGH',
    severity: 'critical',
    category: 'identity',
    title: 'High-Risk User (Identity Protection)',
    description: 'User flagged as high risk by Azure Identity Protection. Account may be compromised.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedAzureUserEntities(affected) : undefined,
  };
}

/**
 * Check for inactive users (90+ days)
 */
export function detectUserInactive(users: AzureUser[], includeDetails: boolean): Finding {
  const now = Date.now();
  const ninetyDaysAgo = now - 90 * 24 * 60 * 60 * 1000;

  const affected = users.filter((u) => {
    if (!u.lastSignInDateTime) return false;
    const lastSignIn = new Date(u.lastSignInDateTime).getTime();
    return lastSignIn < ninetyDaysAgo;
  });

  return {
    type: 'AZURE_USER_INACTIVE',
    severity: 'high',
    category: 'accounts',
    title: 'Inactive User (90+ days)',
    description: 'User account inactive for 90+ days. Should be disabled or deleted.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedAzureUserEntities(affected) : undefined,
  };
}

/**
 * Check for users with password never expires
 */
export function detectPasswordNeverExpires(users: AzureUser[], includeDetails: boolean): Finding {
  const affected = users.filter((u) => {
    return (u as any).passwordPolicies?.includes('DisablePasswordExpiration');
  });

  return {
    type: 'AZURE_USER_PASSWORD_NEVER_EXPIRES',
    severity: 'high',
    category: 'accounts',
    title: 'Password Never Expires',
    description: 'User password expiration disabled. Increases risk of credential compromise.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedAzureUserEntities(affected) : undefined,
  };
}

/**
 * Check for medium-risk users (Identity Protection)
 */
export function detectRiskyUserMedium(users: AzureUser[], includeDetails: boolean): Finding {
  const affected = users.filter((u) => {
    const riskLevel = (u as any).riskLevel;
    return riskLevel === 'medium';
  });

  return {
    type: 'AZURE_RISKY_USER_MEDIUM',
    severity: 'high',
    category: 'identity',
    title: 'Medium-Risk User (Identity Protection)',
    description: 'User flagged as medium risk by Azure Identity Protection. Unusual sign-in activity detected.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedAzureUserEntities(affected) : undefined,
  };
}

/**
 * Check for old passwords (180+ days)
 */
export function detectPasswordOld(users: AzureUser[], includeDetails: boolean): Finding {
  const now = Date.now();
  const sixMonthsAgo = now - 180 * 24 * 60 * 60 * 1000;

  const affected = users.filter((u) => {
    const lastPasswordChange = (u as any).lastPasswordChangeDateTime;
    if (!lastPasswordChange) return false;
    return new Date(lastPasswordChange).getTime() < sixMonthsAgo;
  });

  return {
    type: 'AZURE_PASSWORD_OLD',
    severity: 'medium',
    category: 'accounts',
    title: 'Old Password (180+ days)',
    description: 'User password not changed for 180+ days. Increases credential compromise risk.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedAzureUserEntities(affected) : undefined,
  };
}

/**
 * Check for users who never signed in
 */
export function detectUserNeverSignedIn(users: AzureUser[], includeDetails: boolean): Finding {
  const affected = users.filter((u) => {
    return u.accountEnabled && !u.lastSignInDateTime;
  });

  return {
    type: 'AZURE_USER_NEVER_SIGNED_IN',
    severity: 'medium',
    category: 'accounts',
    title: 'User Never Signed In',
    description: 'Enabled account that has never been used. Orphaned account should be removed.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedAzureUserEntities(affected) : undefined,
  };
}

/**
 * Check for unlicensed users
 */
export function detectUserUnlicensed(users: AzureUser[], includeDetails: boolean): Finding {
  const affected = users.filter((u) => {
    const licenses = (u as any).assignedLicenses;
    return u.accountEnabled && (!licenses || licenses.length === 0);
  });

  return {
    type: 'AZURE_USER_UNLICENSED',
    severity: 'medium',
    category: 'accounts',
    title: 'Unlicensed Active User',
    description: 'Active user without assigned license. May indicate configuration issue.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedAzureUserEntities(affected) : undefined,
  };
}

/**
 * Check for external users with Member type
 */
export function detectUserExternalMember(users: AzureUser[], includeDetails: boolean): Finding {
  const affected = users.filter((u) => {
    const userType = (u as any).userType;
    const isExternal = u.userPrincipalName?.includes('#EXT#');
    return userType === 'Member' && isExternal;
  });

  return {
    type: 'AZURE_USER_EXTERNAL_MEMBER',
    severity: 'medium',
    category: 'accounts',
    title: 'External User as Member',
    description: 'External domain user configured as Member instead of Guest. Security misconfiguration.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedAzureUserEntities(affected) : undefined,
  };
}

/**
 * Detect all user security vulnerabilities
 */
export function detectUserSecurityVulnerabilities(
  users: AzureUser[],
  roles: Map<string, string[]>,
  includeDetails: boolean
): Finding[] {
  return [
    detectGlobalAdminNoMfa(users, roles, includeDetails),
    detectPrivilegedUserNoMfa(users, roles, includeDetails),
    detectRiskyUserHigh(users, includeDetails),
    detectUserInactive(users, includeDetails),
    detectPasswordNeverExpires(users, includeDetails),
    detectRiskyUserMedium(users, includeDetails),
    detectPasswordOld(users, includeDetails),
    detectUserNeverSignedIn(users, includeDetails),
    detectUserUnlicensed(users, includeDetails),
    detectUserExternalMember(users, includeDetails),
  ].filter((finding) => finding.count > 0);
}
