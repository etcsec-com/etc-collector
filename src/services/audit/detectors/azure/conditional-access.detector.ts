/**
 * Conditional Access Detector for Azure AD
 *
 * Detects Conditional Access policy vulnerabilities in Azure AD/Entra ID.
 * Story 1.8: Azure Vulnerability Detection Engine
 *
 * Vulnerabilities detected (6):
 * CRITICAL (2):
 * - AZURE_NO_MFA_CA_POLICY
 * - AZURE_NO_LEGACY_AUTH_BLOCK
 *
 * MEDIUM (3):
 * - AZURE_CA_POLICY_DISABLED
 * - AZURE_CA_POLICY_HAS_EXCLUSIONS
 * - AZURE_NO_DEVICE_COMPLIANCE_CA
 *
 * LOW (1):
 * - AZURE_CA_POLICY_REPORT_ONLY
 */

import { AzurePolicy } from '../../../../types/azure.types';
import { Finding } from '../../../../types/finding.types';

/**
 * Check for absence of MFA enforcement via Conditional Access
 */
export function detectNoMfaCaPolicy(policies: AzurePolicy[], includeDetails: boolean): Finding {
  const hasMfaPolicy = policies.some((policy) => {
    if (policy.state !== 'enabled') return false;

    const grantControls = (policy as any).grantControls;
    if (!grantControls) return false;

    const builtInControls = grantControls.builtInControls || [];
    return builtInControls.includes('mfa');
  });

  return {
    type: 'AZURE_NO_MFA_CA_POLICY',
    severity: 'critical',
    category: 'conditionalAccess',
    title: 'No MFA Enforcement via Conditional Access',
    description: 'No Conditional Access policy enforcing MFA. Users can authenticate without multi-factor authentication.',
    count: hasMfaPolicy ? 0 : 1,
    affectedEntities: includeDetails && !hasMfaPolicy ? ['Tenant-wide'] : undefined,
  };
}

/**
 * Check for absence of legacy authentication blocking
 */
export function detectNoLegacyAuthBlock(policies: AzurePolicy[], includeDetails: boolean): Finding {
  const hasLegacyAuthBlock = policies.some((policy) => {
    if (policy.state !== 'enabled') return false;

    const conditions = (policy as any).conditions;
    const clientAppTypes = conditions?.clientAppTypes || [];

    // Check if policy blocks legacy authentication clients
    const blocksLegacyAuth =
      clientAppTypes.includes('exchangeActiveSync') ||
      clientAppTypes.includes('other') ||
      (clientAppTypes.includes('all') && (policy as any).grantControls?.builtInControls?.includes('block'));

    return blocksLegacyAuth;
  });

  return {
    type: 'AZURE_NO_LEGACY_AUTH_BLOCK',
    severity: 'critical',
    category: 'conditionalAccess',
    title: 'No Policy Blocking Legacy Authentication',
    description: 'No Conditional Access policy blocking legacy authentication protocols. Legacy auth bypasses MFA.',
    count: hasLegacyAuthBlock ? 0 : 1,
    affectedEntities: includeDetails && !hasLegacyAuthBlock ? ['Tenant-wide'] : undefined,
  };
}

/**
 * Check for disabled Conditional Access policies
 */
export function detectCaPolicyDisabled(policies: AzurePolicy[], includeDetails: boolean): Finding {
  const affected = policies.filter((policy) => {
    return policy.state === 'disabled';
  });

  return {
    type: 'AZURE_CA_POLICY_DISABLED',
    severity: 'medium',
    category: 'conditionalAccess',
    title: 'Disabled Conditional Access Policy',
    description: 'Conditional Access policy is disabled. Security controls are not being enforced.',
    count: affected.length,
    affectedEntities: includeDetails ? affected.map((p) => p.displayName) : undefined,
  };
}

/**
 * Check for CA policies with user/group exclusions
 */
export function detectCaPolicyHasExclusions(policies: AzurePolicy[], includeDetails: boolean): Finding {
  const affected = policies.filter((policy) => {
    if (policy.state !== 'enabled') return false;

    const conditions = (policy as any).conditions;
    const users = conditions?.users;

    const hasExclusions =
      (users?.excludeUsers && users.excludeUsers.length > 0) ||
      (users?.excludeGroups && users.excludeGroups.length > 0) ||
      (users?.excludeRoles && users.excludeRoles.length > 0);

    return hasExclusions;
  });

  return {
    type: 'AZURE_CA_POLICY_HAS_EXCLUSIONS',
    severity: 'medium',
    category: 'conditionalAccess',
    title: 'Conditional Access Policy with Exclusions',
    description: 'CA policy has user, group, or role exclusions. Excluded identities bypass security controls.',
    count: affected.length,
    affectedEntities: includeDetails ? affected.map((p) => p.displayName) : undefined,
  };
}

/**
 * Check for absence of device compliance requirement
 */
export function detectNoDeviceComplianceCa(policies: AzurePolicy[], includeDetails: boolean): Finding {
  const hasDeviceCompliancePolicy = policies.some((policy) => {
    if (policy.state !== 'enabled') return false;

    const grantControls = (policy as any).grantControls;
    if (!grantControls) return false;

    const builtInControls = grantControls.builtInControls || [];
    return builtInControls.includes('compliantDevice') || builtInControls.includes('domainJoinedDevice');
  });

  return {
    type: 'AZURE_NO_DEVICE_COMPLIANCE_CA',
    severity: 'medium',
    category: 'conditionalAccess',
    title: 'No Device Compliance Requirement',
    description: 'No Conditional Access policy requiring compliant devices. Unmanaged devices can access resources.',
    count: hasDeviceCompliancePolicy ? 0 : 1,
    affectedEntities: includeDetails && !hasDeviceCompliancePolicy ? ['Tenant-wide'] : undefined,
  };
}

/**
 * Check for CA policies in report-only mode
 */
export function detectCaPolicyReportOnly(policies: AzurePolicy[], includeDetails: boolean): Finding {
  const affected = policies.filter((policy) => {
    return policy.state === 'enabledForReportingButNotEnforced';
  });

  return {
    type: 'AZURE_CA_POLICY_REPORT_ONLY',
    severity: 'low',
    category: 'conditionalAccess',
    title: 'Conditional Access Policy in Report-Only Mode',
    description: 'CA policy in report-only mode. Security controls are not being enforced, only logged.',
    count: affected.length,
    affectedEntities: includeDetails ? affected.map((p) => p.displayName) : undefined,
  };
}

/**
 * Detect all Conditional Access vulnerabilities
 */
export function detectConditionalAccessVulnerabilities(
  policies: AzurePolicy[],
  includeDetails: boolean
): Finding[] {
  return [
    detectNoMfaCaPolicy(policies, includeDetails),
    detectNoLegacyAuthBlock(policies, includeDetails),
    detectCaPolicyDisabled(policies, includeDetails),
    detectCaPolicyHasExclusions(policies, includeDetails),
    detectNoDeviceComplianceCa(policies, includeDetails),
    detectCaPolicyReportOnly(policies, includeDetails),
  ].filter((finding) => finding.count > 0);
}
