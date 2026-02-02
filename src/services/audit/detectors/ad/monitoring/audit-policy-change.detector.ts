/**
 * Audit Policy Change Detector
 *
 * Detects if policy change events are not being audited.
 */

import { ADDomain } from '../../../../../types/ad.types';
import { Finding } from '../../../../../types/finding.types';
import { GpoSecuritySettings } from '../../../../../providers/smb/smb.provider';

/**
 * Detect if policy change events are not being audited
 */
export function detectAuditPolicyChangeDisabled(
  gpoSettings: GpoSecuritySettings | null,
  domain: ADDomain | null,
  includeDetails: boolean
): Finding {
  if (gpoSettings?.auditPolicies && gpoSettings.auditPolicies.length > 0) {
    const auditPolicies = gpoSettings.auditPolicies;

    const hasPolicyChangeAudit = auditPolicies.some(
      (p) => p.category.includes('Policy Change') && (p.success || p.failure)
    );

    return {
      type: 'AUDIT_POLICY_CHANGE_DISABLED',
      severity: 'high',
      category: 'monitoring',
      title: 'Policy Changes Not Audited',
      description:
        'Policy change events are not being audited. GPO modifications and security policy changes will not be logged.',
      count: hasPolicyChangeAudit ? 0 : 1,
      affectedEntities: includeDetails && !hasPolicyChangeAudit && domain ? [domain.dn] : undefined,
      details: !hasPolicyChangeAudit
        ? {
            recommendation: 'Enable "Audit Policy Change" for both Success and Failure.',
            attacksUndetected: [
              'GPO poisoning',
              'Security policy weakening',
              'Audit policy tampering',
              'Firewall rule modifications',
            ],
          }
        : undefined,
    };
  }

  return {
    type: 'AUDIT_POLICY_CHANGE_DISABLED',
    severity: 'high',
    category: 'monitoring',
    title: 'Policy Change Audit Configuration Unknown',
    description: 'Unable to determine policy change audit configuration.',
    count: 0,
  };
}
