/**
 * AUDIT_LOG_RETENTION_SHORT - Log retention below requirements
 * Frameworks: SOX Section 802, HIPAA 164.312(b), PCI-DSS 10.7
 * Checks if audit log retention meets compliance requirements (1 year minimum)
 */

import { Finding } from '../../../../../../types/finding.types';
import { GpoSecuritySettings } from '../../../../../../providers/smb/smb.provider';

export function detectAuditLogRetentionShort(
  gpoSettings: GpoSecuritySettings | null,
  _includeDetails: boolean
): Finding {
  const issues: string[] = [];

  // Check if audit policy is configured (indicates logging is set up)
  if (!gpoSettings?.auditPolicies || gpoSettings.auditPolicies.length === 0) {
    issues.push('Audit policy not configured - log retention cannot be verified');
  } else {
    // Check if essential events are being audited (prerequisite for retention)
    const hasSecurityAudit = gpoSettings.auditPolicies.some(
      (p) => p.category.includes('Logon') || p.category.includes('Account')
    );
    if (!hasSecurityAudit) {
      issues.push('Security events not being audited - retention policy meaningless without logging');
    }
  }

  // Note: Actual log retention settings are in Windows Event Log configuration
  // which requires additional GPO parsing or WMI queries not currently available
  // This check ensures audit infrastructure exists as prerequisite
  if (issues.length === 0) {
    issues.push('Log retention period should be verified manually (1 year minimum for compliance)');
  }

  return {
    type: 'AUDIT_LOG_RETENTION_SHORT',
    severity: 'high',
    category: 'compliance',
    title: 'Audit Log Retention Below Requirements',
    description:
      'Audit log retention period may not meet compliance requirements (1 year minimum). Required by SOX Section 802, HIPAA 164.312(b), PCI-DSS 10.7.',
    count: issues.length > 0 ? 1 : 0,
    details: issues.length > 0 ? {
      violations: issues,
      frameworks: ['SOX', 'HIPAA', 'PCI-DSS'],
      controls: ['Section 802', '164.312(b)', '10.7'],
      recommendation: 'Configure log retention for minimum 1 year with SIEM integration',
    } : undefined,
  };
}
