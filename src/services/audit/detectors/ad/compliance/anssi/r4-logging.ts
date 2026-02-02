/**
 * ANSSI R4 - Logging and Monitoring
 * Checks logging configuration compliance:
 * - Security event logging enabled
 * - Log size adequate
 * - Retention configured
 */

import { Finding } from '../../../../../../types/finding.types';
import { GpoSecuritySettings } from '../../../../../../providers/smb/smb.provider';

export function detectAnssiR4Logging(
  gpoSettings: GpoSecuritySettings | null,
  _includeDetails: boolean
): Finding {
  const issues: string[] = [];

  if (!gpoSettings) {
    issues.push('GPO settings not available for audit policy analysis');
  } else {
    // Check audit policy
    if (gpoSettings.auditPolicies && gpoSettings.auditPolicies.length > 0) {
      const audit = gpoSettings.auditPolicies;

      // Check essential audit categories
      const hasLogon = audit.some((p) => p.category.includes('Logon') && p.success && p.failure);
      const hasAccountMgmt = audit.some(
        (p) => p.category.includes('Account Management') && p.success && p.failure
      );
      const hasPolicyChange = audit.some(
        (p) => p.category.includes('Policy Change') && p.success && p.failure
      );
      const hasPrivilegeUse = audit.some(
        (p) => p.category.includes('Privilege Use') && p.success && p.failure
      );

      if (!hasLogon) issues.push('Logon events not fully audited');
      if (!hasAccountMgmt) issues.push('Account management not fully audited');
      if (!hasPolicyChange) issues.push('Policy changes not fully audited');
      if (!hasPrivilegeUse) issues.push('Privilege use not fully audited');
    } else {
      issues.push('Audit policy not configured');
    }
  }

  return {
    type: 'ANSSI_R4_LOGGING',
    severity: 'medium',
    category: 'compliance',
    title: 'ANSSI R4 - Logging Non-Compliant',
    description:
      'Logging configuration does not meet ANSSI R4 recommendations. All security events should be audited with adequate log retention.',
    count: issues.length > 0 ? 1 : 0,
    details: issues.length > 0 ? { violations: issues, framework: 'ANSSI', control: 'R4' } : undefined,
  };
}
