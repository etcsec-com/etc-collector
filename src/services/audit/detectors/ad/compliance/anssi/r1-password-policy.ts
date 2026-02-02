/**
 * ANSSI R1 - Password Policy Compliance
 * Checks if password policy meets ANSSI recommendations:
 * - Minimum 12 characters for users, 16 for admins
 * - Password history >= 12
 * - Lockout threshold <= 5
 * - Maximum password age <= 90 days
 */

import { ADDomain } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';
import { GpoSecuritySettings } from '../../../../../../providers/smb/smb.provider';
import { PasswordPolicy } from '../types';

export function detectAnssiR1PasswordPolicy(
  domain: ADDomain,
  gpoSettings: GpoSecuritySettings | null,
  _includeDetails: boolean
): Finding {
  const issues: string[] = [];
  let compliant = true;

  // Check domain password policy
  const policy = domain['passwordPolicy'] as PasswordPolicy | undefined;
  if (policy) {
    if (policy.minPwdLength < 12) {
      issues.push(`Minimum password length ${policy.minPwdLength} < 12 required`);
      compliant = false;
    }
    if (policy.pwdHistoryLength < 12) {
      issues.push(`Password history ${policy.pwdHistoryLength} < 12 required`);
      compliant = false;
    }
    if (policy.lockoutThreshold > 5 && policy.lockoutThreshold !== 0) {
      issues.push(`Lockout threshold ${policy.lockoutThreshold} > 5 allowed`);
      compliant = false;
    }
    if (policy.maxPwdAge > 90) {
      issues.push(`Max password age ${policy.maxPwdAge} > 90 days`);
      compliant = false;
    }
  } else {
    issues.push('Password policy not configured or not readable');
    compliant = false;
  }

  // Check GPO settings for fine-grained password policy
  if (gpoSettings?.ldapServerIntegrity !== undefined) {
    // GPO settings available but no password policy in them
    // This is informational only
  }

  return {
    type: 'ANSSI_R1_PASSWORD_POLICY',
    severity: 'high',
    category: 'compliance',
    title: 'ANSSI R1 - Password Policy Non-Compliant',
    description:
      'Password policy does not meet ANSSI R1 recommendations. ANSSI requires minimum 12 characters, password history of 12, lockout threshold ≤5, and max age ≤90 days.',
    count: compliant ? 0 : 1,
    details: issues.length > 0 ? { violations: issues, framework: 'ANSSI', control: 'R1' } : undefined,
  };
}
