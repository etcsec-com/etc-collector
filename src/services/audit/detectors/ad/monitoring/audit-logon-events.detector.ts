/**
 * Audit Logon Events Detector
 *
 * Detects if logon events are not being audited.
 * Checks for "Account Logon" and "Logon/Logoff" audit categories.
 */

import { ADDomain } from '../../../../../types/ad.types';
import { Finding } from '../../../../../types/finding.types';
import { GpoSecuritySettings } from '../../../../../providers/smb/smb.provider';

/**
 * Detect if logon events are not being audited
 * Checks for "Account Logon" and "Logon/Logoff" audit categories
 */
export function detectAuditLogonEventsDisabled(
  gpoSettings: GpoSecuritySettings | null,
  domain: ADDomain | null,
  includeDetails: boolean
): Finding {
  if (gpoSettings?.auditPolicies && gpoSettings.auditPolicies.length > 0) {
    const auditPolicies = gpoSettings.auditPolicies;

    // Check for logon-related audit categories
    const logonCategories = ['Account Logon', 'Logon/Logoff', 'Logon'];
    const hasLogonAudit = auditPolicies.some(
      (p) => logonCategories.some((cat) => p.category.includes(cat)) && (p.success || p.failure)
    );

    return {
      type: 'AUDIT_LOGON_EVENTS_DISABLED',
      severity: 'high',
      category: 'monitoring',
      title: 'Logon Events Not Audited',
      description:
        'Logon events are not being audited. Failed and successful authentication attempts will not be logged, hindering intrusion detection.',
      count: hasLogonAudit ? 0 : 1,
      affectedEntities: includeDetails && !hasLogonAudit && domain ? [domain.dn] : undefined,
      details: !hasLogonAudit
        ? {
            recommendation:
              'Enable "Audit Logon Events" and "Audit Account Logon Events" for both Success and Failure.',
            missingCategories: logonCategories,
            attacksUndetected: [
              'Brute force attacks',
              'Password spraying',
              'Pass-the-hash',
              'Kerberos ticket attacks',
            ],
          }
        : undefined,
    };
  }

  return {
    type: 'AUDIT_LOGON_EVENTS_DISABLED',
    severity: 'high',
    category: 'monitoring',
    title: 'Logon Audit Configuration Unknown',
    description: 'Unable to determine logon audit configuration. Manual review recommended.',
    count: 0,
    details: {
      note: 'GPO audit settings not available. Check Advanced Audit Policy Configuration manually.',
    },
  };
}
