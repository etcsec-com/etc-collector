/**
 * Audit Privilege Use Detector
 *
 * Detects if privilege use is not being audited.
 */

import { ADDomain } from '../../../../../types/ad.types';
import { Finding } from '../../../../../types/finding.types';
import { GpoSecuritySettings } from '../../../../../providers/smb/smb.provider';

/**
 * Detect if privilege use is not being audited
 */
export function detectAuditPrivilegeUseDisabled(
  gpoSettings: GpoSecuritySettings | null,
  domain: ADDomain | null,
  includeDetails: boolean
): Finding {
  if (gpoSettings?.auditPolicies && gpoSettings.auditPolicies.length > 0) {
    const auditPolicies = gpoSettings.auditPolicies;

    const hasPrivilegeUseAudit = auditPolicies.some(
      (p) => p.category.includes('Privilege Use') && (p.success || p.failure)
    );

    return {
      type: 'AUDIT_PRIVILEGE_USE_DISABLED',
      severity: 'medium',
      category: 'monitoring',
      title: 'Privilege Use Not Audited',
      description:
        'Privilege use events are not being audited. Sensitive privilege usage will not be logged.',
      count: hasPrivilegeUseAudit ? 0 : 1,
      affectedEntities: includeDetails && !hasPrivilegeUseAudit && domain ? [domain.dn] : undefined,
      details: !hasPrivilegeUseAudit
        ? {
            recommendation: 'Enable "Audit Privilege Use" for Failure events at minimum.',
            attacksUndetected: [
              'Privilege abuse',
              'SeDebugPrivilege exploitation',
              'Token manipulation',
              'Impersonation attacks',
            ],
          }
        : undefined,
    };
  }

  return {
    type: 'AUDIT_PRIVILEGE_USE_DISABLED',
    severity: 'medium',
    category: 'monitoring',
    title: 'Privilege Use Audit Configuration Unknown',
    description: 'Unable to determine privilege use audit configuration.',
    count: 0,
  };
}
