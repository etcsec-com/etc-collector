/**
 * Privilege Security Vulnerability Detector for Azure AD
 *
 * Detects privileged access vulnerabilities in Azure AD/Entra ID.
 * Story 1.8: Azure Vulnerability Detection Engine
 *
 * Vulnerabilities detected (4):
 * CRITICAL (2):
 * - AZURE_GUEST_PRIVILEGED_ACCESS
 * - AZURE_SERVICE_ACCOUNT_PRIVILEGED
 *
 * HIGH (2):
 * - AZURE_TOO_MANY_GLOBAL_ADMINS
 * - AZURE_GROUP_DYNAMIC_RISKY_RULE
 */

import { AzureUser, AzureGroup } from '../../../../types/azure.types';
import { Finding } from '../../../../types/finding.types';
import { toAffectedAzureUserEntities, toAffectedAzureGroupEntities } from '../../../../utils/entity-converter';

/**
 * Check for guest users with privileged roles
 */
export function detectGuestPrivilegedAccess(
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
    '729827e3-9c14-49f7-bb1b-9608f156bbb8', // Helpdesk Administrator
    'b0f54661-2d74-4c50-afa3-1ec803f12efe', // Billing Administrator
  ];

  const affected = users.filter((u) => {
    const isGuest = (u as any).userType === 'Guest';
    const userRoles = roles.get(u.id) || [];
    const hasPrivilegedRole = userRoles.some((r) => privilegedRoleIds.includes(r));

    return isGuest && hasPrivilegedRole;
  });

  return {
    type: 'AZURE_GUEST_PRIVILEGED_ACCESS',
    severity: 'critical',
    category: 'privilegedAccess',
    title: 'Guest User with Privileged Role',
    description: 'Guest user from external domain assigned privileged role. High risk from external account compromise.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedAzureUserEntities(affected) : undefined,
  };
}

/**
 * Check for service accounts with privileged roles
 */
export function detectServiceAccountPrivileged(
  users: AzureUser[],
  roles: Map<string, string[]>,
  includeDetails: boolean
): Finding {
  const privilegedRoleIds = [
    '62e90394-69f5-4237-9190-012177145e10', // Global Administrator
    'e8611ab8-c189-46e8-94e1-60213ab1f814', // Privileged Role Administrator
    '194ae4cb-b126-40b2-bd5b-6091b380977d', // Security Administrator
  ];

  const affected = users.filter((u) => {
    // Service accounts typically: no sign-in, name patterns, or application type
    const isServiceAccount =
      !u.lastSignInDateTime ||
      u.userPrincipalName?.toLowerCase().includes('svc') ||
      u.userPrincipalName?.toLowerCase().includes('service') ||
      u.displayName?.toLowerCase().includes('service') ||
      (u as any).userType === 'Application';

    const userRoles = roles.get(u.id) || [];
    const hasPrivilegedRole = userRoles.some((r) => privilegedRoleIds.includes(r));

    return isServiceAccount && hasPrivilegedRole;
  });

  return {
    type: 'AZURE_SERVICE_ACCOUNT_PRIVILEGED',
    severity: 'critical',
    category: 'privilegedAccess',
    title: 'Service Account with Privileged Role',
    description: 'Service/application account with privileged role. Service accounts should use managed identities.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedAzureUserEntities(affected) : undefined,
  };
}

/**
 * Check for excessive number of Global Administrators (>5)
 */
export function detectTooManyGlobalAdmins(
  users: AzureUser[],
  roles: Map<string, string[]>,
  includeDetails: boolean
): Finding {
  const globalAdminRoleId = '62e90394-69f5-4237-9190-012177145e10';

  const affected = users.filter((u) => {
    const userRoles = roles.get(u.id) || [];
    return userRoles.includes(globalAdminRoleId);
  });

  const threshold = 5;
  const count = affected.length > threshold ? 1 : 0;

  return {
    type: 'AZURE_TOO_MANY_GLOBAL_ADMINS',
    severity: 'high',
    category: 'privilegedAccess',
    title: 'Too Many Global Administrators',
    description: `Tenant has ${affected.length} Global Administrators (recommended: ≤${threshold}). Excessive admin accounts increase attack surface.`,
    count,
    affectedEntities: includeDetails && count > 0 ? [`${affected.length} Global Admins`] : undefined,
  };
}

/**
 * Check for dynamic groups with risky membership rules
 */
export function detectGroupDynamicRiskyRule(groups: AzureGroup[], includeDetails: boolean): Finding {
  const riskyPatterns = [
    'accountEnabled eq true', // Too broad
    'userType eq "Member"', // All members
    'userType eq "Guest"', // All guests (less risky but broad)
    'objectId ne null', // Everyone
    'mail contains "@"', // Everyone with email
  ];

  const affected = groups.filter((g) => {
    const membershipRule = (g as any).membershipRule;
    if (!membershipRule || (g as any).groupTypes?.includes('DynamicMembership') === false) {
      return false;
    }

    // Check if rule contains risky patterns
    const lowerRule = membershipRule.toLowerCase();
    return riskyPatterns.some((pattern) => lowerRule.includes(pattern.toLowerCase()));
  });

  return {
    type: 'AZURE_GROUP_DYNAMIC_RISKY_RULE',
    severity: 'high',
    category: 'privilegedAccess',
    title: 'Dynamic Group with Risky Membership Rule',
    description: 'Dynamic group with overly permissive membership rule. May grant unintended access.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedAzureGroupEntities(affected) : undefined,
  };
}

/**
 * Detect all privilege security vulnerabilities
 */
export function detectPrivilegeSecurityVulnerabilities(
  users: AzureUser[],
  groups: AzureGroup[],
  roles: Map<string, string[]>,
  includeDetails: boolean
): Finding[] {
  return [
    detectGuestPrivilegedAccess(users, roles, includeDetails),
    detectServiceAccountPrivileged(users, roles, includeDetails),
    detectTooManyGlobalAdmins(users, roles, includeDetails),
    detectGroupDynamicRiskyRule(groups, includeDetails),
  ].filter((finding) => finding.count > 0);
}
