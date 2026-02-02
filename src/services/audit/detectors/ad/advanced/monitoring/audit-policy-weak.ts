/**
 * Audit Policy Weak Detector
 * Check if audit policy is weak/incomplete
 * Requires GPO settings from SYSVOL
 */

import { ADDomain } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';
import { GpoSecuritySettings } from '../types';

export function detectAuditPolicyWeak(
  gpoSettings: GpoSecuritySettings | null,
  domain: ADDomain | null,
  includeDetails: boolean
): Finding {
  // Critical audit categories that should be enabled
  const criticalAuditCategories = [
    'Account Logon',
    'Account Management',
    'Logon/Logoff',
    'Object Access',
    'Policy Change',
    'Privilege Use',
    'System',
  ];

  if (gpoSettings && gpoSettings.auditPolicies && gpoSettings.auditPolicies.length > 0) {
    const configuredCategories = new Set(gpoSettings.auditPolicies.map((p) => p.category));
    const missingCategories = criticalAuditCategories.filter((cat) => !configuredCategories.has(cat));

    // Check if critical events are being audited
    const hasWeakAudit = missingCategories.length > 0;

    return {
      type: 'AUDIT_POLICY_WEAK',
      severity: 'medium',
      category: 'advanced',
      title: 'Audit Policy Incomplete',
      description:
        'Domain audit policy does not cover all critical security events. Attacks may go undetected.',
      count: hasWeakAudit ? 1 : 0,
      affectedEntities: includeDetails && hasWeakAudit && domain ? [domain.dn] : undefined,
      details: hasWeakAudit
        ? {
            recommendation: 'Configure Advanced Audit Policy to audit all critical security categories.',
            missingCategories,
            configuredCategories: Array.from(configuredCategories),
          }
        : undefined,
    };
  }

  return {
    type: 'AUDIT_POLICY_WEAK',
    severity: 'medium',
    category: 'advanced',
    title: 'Audit Policy Configuration Unknown',
    description: 'Unable to determine audit policy configuration. Manual review recommended.',
    count: 0,
    details: {
      note: 'GPO audit settings not available. Check Advanced Audit Policy Configuration manually.',
      requiredCategories: criticalAuditCategories,
    },
  };
}
