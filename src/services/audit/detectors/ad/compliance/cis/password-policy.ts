/**
 * CIS Password Policy (2.3.1.x)
 * Checks CIS Benchmark password policy recommendations
 */

import { ADDomain } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';
import { PasswordPolicy } from '../types';

export function detectCisPasswordPolicy(
  domain: ADDomain,
  _includeDetails: boolean
): Finding {
  const issues: string[] = [];

  const policy = domain['passwordPolicy'] as PasswordPolicy | undefined;
  if (policy) {
    // CIS recommends minimum 14 characters
    if (policy.minPwdLength < 14) {
      issues.push(`Minimum password length ${policy.minPwdLength} < 14 (CIS 1.1.1)`);
    }
    // CIS recommends password history of 24
    if (policy.pwdHistoryLength < 24) {
      issues.push(`Password history ${policy.pwdHistoryLength} < 24 (CIS 1.1.2)`);
    }
    // CIS recommends max password age 365 days or less
    if (policy.maxPwdAge > 365) {
      issues.push(`Max password age ${policy.maxPwdAge} > 365 days (CIS 1.1.3)`);
    }
    // CIS recommends minimum password age of 1 day
    if (policy.minPwdAge < 1) {
      issues.push(`Min password age ${policy.minPwdAge} < 1 day (CIS 1.1.4)`);
    }
    // Complexity should be enabled
    if (!policy.complexityEnabled) {
      issues.push('Password complexity not enabled (CIS 1.1.5)');
    }
    // Reversible encryption should be disabled
    if (policy.reversibleEncryption) {
      issues.push('Reversible encryption enabled (CIS 1.1.6)');
    }
  } else {
    issues.push('Password policy not available');
  }

  return {
    type: 'CIS_PASSWORD_POLICY',
    severity: 'high',
    category: 'compliance',
    title: 'CIS Benchmark - Password Policy Non-Compliant',
    description:
      'Password policy does not meet CIS Benchmark recommendations. Review and update password policy settings.',
    count: issues.length > 0 ? 1 : 0,
    details: issues.length > 0 ? { violations: issues, framework: 'CIS', control: '1.1.x' } : undefined,
  };
}
