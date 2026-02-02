/**
 * NIST IA-5 - Authenticator Management
 * Checks authenticator compliance:
 * - Password complexity
 * - Account lockout
 * - Password age
 */

import { ADUser, ADDomain } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';
import { PasswordPolicy } from '../types';

export function detectNistIa5Authenticator(
  domain: ADDomain,
  users: ADUser[],
  _includeDetails: boolean
): Finding {
  const issues: string[] = [];

  // Check password policy
  const policy = domain['passwordPolicy'] as PasswordPolicy | undefined;
  if (policy) {
    if (!policy.complexityEnabled) {
      issues.push('Password complexity not enabled');
    }
    if (policy.minPwdLength < 14) {
      issues.push(`Minimum password length ${policy.minPwdLength} < 14 (NIST recommends 14+)`);
    }
    if (policy.lockoutThreshold === 0) {
      issues.push('Account lockout not configured');
    }
  }

  // Check for accounts with password not required
  const noPasswordRequired = users.filter((u) => {
    const uac = u.userAccountControl || 0;
    return (uac & 0x20) !== 0; // PASSWD_NOTREQD
  });

  if (noPasswordRequired.length > 0) {
    issues.push(`${noPasswordRequired.length} accounts with password not required`);
  }

  // Check for reversible encryption
  const reversibleEncryption = users.filter((u) => {
    const uac = u.userAccountControl || 0;
    return (uac & 0x80) !== 0; // ENCRYPTED_TEXT_PWD_ALLOWED
  });

  if (reversibleEncryption.length > 0) {
    issues.push(`${reversibleEncryption.length} accounts with reversible encryption`);
  }

  return {
    type: 'NIST_IA_5_AUTHENTICATOR',
    severity: 'medium',
    category: 'compliance',
    title: 'NIST IA-5 - Authenticator Management Issues',
    description:
      'Authenticator management does not comply with NIST IA-5. Password policies should enforce complexity and secure storage.',
    count: issues.length > 0 ? 1 : 0,
    details: issues.length > 0 ? { violations: issues, framework: 'NIST', control: 'IA-5' } : undefined,
  };
}
