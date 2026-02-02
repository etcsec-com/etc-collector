/**
 * DISA STIG V-220857 - Account Policies
 * Checks DISA STIG account policy requirements
 */

import { ADUser, ADDomain } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';
import { PasswordPolicy } from '../types';

export function detectDisaAccountPolicies(
  domain: ADDomain,
  users: ADUser[],
  _includeDetails: boolean
): Finding {
  const issues: string[] = [];

  const policy = domain['passwordPolicy'] as PasswordPolicy | undefined;
  if (policy) {
    // DISA requires minimum 15 characters for privileged accounts
    if (policy.minPwdLength < 15) {
      issues.push(`Min password length ${policy.minPwdLength} < 15 (V-220857)`);
    }
    // Lockout duration must be 0 (until admin unlock) or >= 15 minutes
    if (policy.lockoutDuration > 0 && policy.lockoutDuration < 15) {
      issues.push(`Lockout duration ${policy.lockoutDuration} min < 15 min (V-220857)`);
    }
    // Lockout threshold must be <= 3
    if (policy.lockoutThreshold > 3) {
      issues.push(`Lockout threshold ${policy.lockoutThreshold} > 3 (V-220857)`);
    }
  }

  // Check for accounts without password expiration (except service accounts)
  const noExpiration = users.filter((u) => {
    const uac = u.userAccountControl || 0;
    const hasNoExpire = (uac & 0x10000) !== 0; // DONT_EXPIRE_PASSWORD
    const isServiceAccount =
      u.sAMAccountName.toLowerCase().includes('svc') ||
      u.sAMAccountName.toLowerCase().includes('service');
    return hasNoExpire && !isServiceAccount;
  });

  if (noExpiration.length > 0) {
    issues.push(`${noExpiration.length} non-service accounts with password never expires (V-220857)`);
  }

  return {
    type: 'DISA_ACCOUNT_POLICIES',
    severity: 'high',
    category: 'compliance',
    title: 'DISA STIG - Account Policies Non-Compliant',
    description:
      'Account policies do not comply with DISA STIG V-220857. Review password and lockout policy settings.',
    count: issues.length > 0 ? 1 : 0,
    details: issues.length > 0 ? { violations: issues, framework: 'DISA', control: 'V-220857' } : undefined,
  };
}
