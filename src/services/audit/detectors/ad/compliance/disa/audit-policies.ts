/**
 * DISA STIG V-220858 - Audit Policies
 * Checks DISA STIG audit policy requirements
 */

import { Finding } from '../../../../../../types/finding.types';
import { GpoSecuritySettings } from '../../../../../../providers/smb/smb.provider';

export function detectDisaAuditPolicies(
  gpoSettings: GpoSecuritySettings | null,
  _includeDetails: boolean
): Finding {
  const issues: string[] = [];

  if (!gpoSettings?.auditPolicies || gpoSettings.auditPolicies.length === 0) {
    issues.push('Audit policy not configured (V-220858)');
  } else {
    const audit = gpoSettings.auditPolicies;

    // DISA requires specific audit categories
    const disaRequirements = [
      { name: 'Account Logon (Success)', check: (a: typeof audit) => a.some((p) => p.category.includes('Logon') && p.success) },
      { name: 'Account Logon (Failure)', check: (a: typeof audit) => a.some((p) => p.category.includes('Logon') && p.failure) },
      { name: 'Account Management (Success)', check: (a: typeof audit) => a.some((p) => p.category.includes('Account Management') && p.success) },
      { name: 'Account Management (Failure)', check: (a: typeof audit) => a.some((p) => p.category.includes('Account Management') && p.failure) },
      { name: 'Policy Change (Success)', check: (a: typeof audit) => a.some((p) => p.category.includes('Policy Change') && p.success) },
      { name: 'Policy Change (Failure)', check: (a: typeof audit) => a.some((p) => p.category.includes('Policy Change') && p.failure) },
      { name: 'Privilege Use (Success)', check: (a: typeof audit) => a.some((p) => p.category.includes('Privilege Use') && p.success) },
      { name: 'Privilege Use (Failure)', check: (a: typeof audit) => a.some((p) => p.category.includes('Privilege Use') && p.failure) },
    ];

    for (const req of disaRequirements) {
      if (!req.check(audit)) {
        issues.push(`${req.name} audit not enabled (V-220858)`);
      }
    }
  }

  return {
    type: 'DISA_AUDIT_POLICIES',
    severity: 'high',
    category: 'compliance',
    title: 'DISA STIG - Audit Policies Non-Compliant',
    description:
      'Audit policies do not comply with DISA STIG V-220858. All required audit categories should be enabled.',
    count: issues.length > 0 ? 1 : 0,
    details: issues.length > 0 ? { violations: issues, framework: 'DISA', control: 'V-220858' } : undefined,
  };
}
