/**
 * NIST AU-2 - Audit Events
 * Checks audit event configuration:
 * - Essential events audited
 * - Audit policy completeness
 */

import { Finding } from '../../../../../../types/finding.types';
import { GpoSecuritySettings } from '../../../../../../providers/smb/smb.provider';

export function detectNistAu2AuditEvents(
  gpoSettings: GpoSecuritySettings | null,
  _includeDetails: boolean
): Finding {
  const issues: string[] = [];

  if (!gpoSettings?.auditPolicies || gpoSettings.auditPolicies.length === 0) {
    issues.push('Audit policy not configured or not readable');
  } else {
    const audit = gpoSettings.auditPolicies;

    // NIST AU-2 required events
    const requiredCategories = [
      'Account Logon',
      'Account Management',
      'Policy Change',
      'System',
      'Object Access',
    ];

    for (const category of requiredCategories) {
      const hasCategory = audit.some(
        (p) => p.category.includes(category) && p.success && p.failure
      );
      if (!hasCategory) {
        issues.push(`${category} not fully audited (success and failure)`);
      }
    }
  }

  return {
    type: 'NIST_AU_2_AUDIT_EVENTS',
    severity: 'medium',
    category: 'compliance',
    title: 'NIST AU-2 - Audit Events Non-Compliant',
    description:
      'Audit event configuration does not comply with NIST AU-2. All security-relevant events should be audited.',
    count: issues.length > 0 ? 1 : 0,
    details: issues.length > 0 ? { violations: issues, framework: 'NIST', control: 'AU-2' } : undefined,
  };
}
