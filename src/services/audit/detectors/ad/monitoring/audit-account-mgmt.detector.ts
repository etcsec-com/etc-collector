/**
 * Audit Account Management Detector
 *
 * Detects if account management events are not being audited.
 */

import { ADDomain } from '../../../../../types/ad.types';
import { Finding } from '../../../../../types/finding.types';
import { GpoSecuritySettings } from '../../../../../providers/smb/smb.provider';

/**
 * Detect if account management events are not being audited
 */
export function detectAuditAccountMgmtDisabled(
  gpoSettings: GpoSecuritySettings | null,
  domain: ADDomain | null,
  includeDetails: boolean
): Finding {
  if (gpoSettings?.auditPolicies && gpoSettings.auditPolicies.length > 0) {
    const auditPolicies = gpoSettings.auditPolicies;

    const hasAccountMgmtAudit = auditPolicies.some(
      (p) => p.category.includes('Account Management') && (p.success || p.failure)
    );

    return {
      type: 'AUDIT_ACCOUNT_MGMT_DISABLED',
      severity: 'high',
      category: 'monitoring',
      title: 'Account Management Not Audited',
      description:
        'Account management events are not being audited. User/group creation, modification, and deletion will not be logged.',
      count: hasAccountMgmtAudit ? 0 : 1,
      affectedEntities: includeDetails && !hasAccountMgmtAudit && domain ? [domain.dn] : undefined,
      details: !hasAccountMgmtAudit
        ? {
            recommendation: 'Enable "Audit Account Management" for both Success and Failure.',
            attacksUndetected: [
              'Unauthorized account creation',
              'Privilege escalation via group membership',
              'Backdoor accounts',
              'Account takeover',
            ],
          }
        : undefined,
    };
  }

  return {
    type: 'AUDIT_ACCOUNT_MGMT_DISABLED',
    severity: 'high',
    category: 'monitoring',
    title: 'Account Management Audit Configuration Unknown',
    description: 'Unable to determine account management audit configuration.',
    count: 0,
  };
}
