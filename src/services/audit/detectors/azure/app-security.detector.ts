/**
 * App Security Vulnerability Detector for Azure AD
 *
 * Detects application and service principal vulnerabilities in Azure AD/Entra ID.
 * Story 1.8: Azure Vulnerability Detection Engine
 *
 * Vulnerabilities detected (7):
 * CRITICAL (1):
 * - AZURE_APP_EXCESSIVE_GRAPH_PERMS
 *
 * HIGH (3):
 * - AZURE_APP_CREDENTIAL_EXPIRED
 * - AZURE_APP_LONG_LIVED_CREDS
 * - AZURE_APP_MULTITENANT_UNVERIFIED
 *
 * MEDIUM (3):
 * - AZURE_APP_CREDENTIAL_EXPIRING
 * - AZURE_SP_DISABLED_WITH_CREDS
 * - AZURE_APP_NO_OWNER
 */

import { AzureApp } from '../../../../types/azure.types';
import { Finding } from '../../../../types/finding.types';
import { toAffectedAppEntities } from '../../../../utils/entity-converter';

/**
 * Check for applications with excessive Microsoft Graph permissions
 */
export function detectAppExcessiveGraphPerms(apps: AzureApp[], includeDetails: boolean): Finding {
  // Well-known Microsoft Graph Application Permission GUIDs
  const dangerousPermissionIds = [
    '1bfefb4e-e0b5-418b-a88f-73c46d1986e9', // Application.ReadWrite.All
    '19dbc75e-c2e2-444c-a770-ec69d8559fc7', // Directory.ReadWrite.All
    '9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8', // RoleManagement.ReadWrite.Directory
    '741f803b-c850-494e-b5df-cde7c675a1ca', // User.ReadWrite.All
    '62a82d76-70ea-41e2-9197-370581804d09', // Group.ReadWrite.All
  ];

  const dangerousPermissionNames = [
    'Application.ReadWrite.All',
    'Directory.ReadWrite.All',
    'RoleManagement.ReadWrite.Directory',
    'User.ReadWrite.All',
    'Group.ReadWrite.All',
  ];

  const affected = apps.filter((app) => {
    const permissions = (app as any).requiredResourceAccess || [];
    return permissions.some((resource: any) => {
      if (resource.resourceAppId === '00000003-0000-0000-c000-000000000000') {
        // Microsoft Graph
        return resource.resourceAccess?.some((access: any) => {
          // Check by GUID
          if (dangerousPermissionIds.includes(access.id)) {
            return true;
          }
          // Check by permission name (if available)
          if (access.value && dangerousPermissionNames.includes(access.value)) {
            return true;
          }
          return false;
        });
      }
      return false;
    });
  });

  return {
    type: 'AZURE_APP_EXCESSIVE_GRAPH_PERMS',
    severity: 'critical',
    category: 'applications',
    title: 'Excessive Microsoft Graph Permissions',
    description: 'Application with high-privilege Graph API permissions. Can access sensitive data across tenant.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedAppEntities(affected) : undefined,
  };
}

/**
 * Check for applications with expired credentials
 */
export function detectAppCredentialExpired(apps: AzureApp[], includeDetails: boolean): Finding {
  const now = Date.now();

  const affected = apps.filter((app) => {
    const credentials = [
      ...((app as any).passwordCredentials || []),
      ...((app as any).keyCredentials || []),
    ];

    return credentials.some((cred: any) => {
      if (!cred.endDateTime) return false;
      return new Date(cred.endDateTime).getTime() < now;
    });
  });

  return {
    type: 'AZURE_APP_CREDENTIAL_EXPIRED',
    severity: 'high',
    category: 'applications',
    title: 'Application Credential Expired',
    description: 'Application with expired secret or certificate. May cause service disruption.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedAppEntities(affected) : undefined,
  };
}

/**
 * Check for applications with long-lived credentials (>1 year)
 */
export function detectAppLongLivedCreds(apps: AzureApp[], includeDetails: boolean): Finding {
  const now = Date.now();
  const oneYearFromNow = now + 365 * 24 * 60 * 60 * 1000;

  const affected = apps.filter((app) => {
    const credentials = [
      ...((app as any).passwordCredentials || []),
      ...((app as any).keyCredentials || []),
    ];

    return credentials.some((cred: any) => {
      if (!cred.endDateTime) return false;
      return new Date(cred.endDateTime).getTime() > oneYearFromNow;
    });
  });

  return {
    type: 'AZURE_APP_LONG_LIVED_CREDS',
    severity: 'high',
    category: 'applications',
    title: 'Long-Lived Application Credentials',
    description: 'Application credential valid for more than 1 year. Increases risk if credential is compromised.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedAppEntities(affected) : undefined,
  };
}

/**
 * Check for unverified multi-tenant applications
 */
export function detectAppMultitenantUnverified(apps: AzureApp[], includeDetails: boolean): Finding {
  const affected = apps.filter((app) => {
    const isMultiTenant = app.signInAudience === 'AzureADMultipleOrgs' || app.signInAudience === 'AzureADandPersonalMicrosoftAccount';
    const isVerified = (app as any).publisherDomain && (app as any).verifiedPublisher;

    return isMultiTenant && !isVerified;
  });

  return {
    type: 'AZURE_APP_MULTITENANT_UNVERIFIED',
    severity: 'high',
    category: 'applications',
    title: 'Unverified Multi-Tenant Application',
    description: 'Multi-tenant application without verified publisher. Users from other tenants may be at risk.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedAppEntities(affected) : undefined,
  };
}

/**
 * Check for applications with credentials expiring soon (30 days)
 */
export function detectAppCredentialExpiring(apps: AzureApp[], includeDetails: boolean): Finding {
  const now = Date.now();
  const thirtyDaysFromNow = now + 30 * 24 * 60 * 60 * 1000;

  const affected = apps.filter((app) => {
    const credentials = [
      ...((app as any).passwordCredentials || []),
      ...((app as any).keyCredentials || []),
    ];

    return credentials.some((cred: any) => {
      if (!cred.endDateTime) return false;
      const expiry = new Date(cred.endDateTime).getTime();
      return expiry > now && expiry < thirtyDaysFromNow;
    });
  });

  return {
    type: 'AZURE_APP_CREDENTIAL_EXPIRING',
    severity: 'medium',
    category: 'applications',
    title: 'Application Credential Expiring Soon',
    description: 'Application credential expiring within 30 days. Action required to avoid service disruption.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedAppEntities(affected) : undefined,
  };
}

/**
 * Check for disabled service principals with credentials
 */
export function detectSpDisabledWithCreds(apps: AzureApp[], includeDetails: boolean): Finding {
  const affected = apps.filter((app) => {
    const isDisabled = (app as any).accountEnabled === false;
    const hasCredentials = ((app as any).passwordCredentials?.length > 0) || ((app as any).keyCredentials?.length > 0);

    return isDisabled && hasCredentials;
  });

  return {
    type: 'AZURE_SP_DISABLED_WITH_CREDS',
    severity: 'medium',
    category: 'applications',
    title: 'Disabled Service Principal with Credentials',
    description: 'Disabled service principal still has active credentials. Credentials should be removed.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedAppEntities(affected) : undefined,
  };
}

/**
 * Check for applications without owners
 */
export function detectAppNoOwner(apps: AzureApp[], includeDetails: boolean): Finding {
  const affected = apps.filter((app) => {
    const owners = (app as any).owners || [];
    return owners.length === 0;
  });

  return {
    type: 'AZURE_APP_NO_OWNER',
    severity: 'medium',
    category: 'applications',
    title: 'Application without Owner',
    description: 'Application has no assigned owners. Orphaned applications are difficult to manage.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedAppEntities(affected) : undefined,
  };
}

/**
 * Detect all application security vulnerabilities
 */
export function detectAppSecurityVulnerabilities(apps: AzureApp[], includeDetails: boolean): Finding[] {
  return [
    detectAppExcessiveGraphPerms(apps, includeDetails),
    detectAppCredentialExpired(apps, includeDetails),
    detectAppLongLivedCreds(apps, includeDetails),
    detectAppMultitenantUnverified(apps, includeDetails),
    detectAppCredentialExpiring(apps, includeDetails),
    detectSpDisabledWithCreds(apps, includeDetails),
    detectAppNoOwner(apps, includeDetails),
  ].filter((finding) => finding.count > 0);
}
