/**
 * Weak Password Policy Detector
 * Check for weak password policy
 */

import { ADDomain } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';

export function detectWeakPasswordPolicy(domain: ADDomain | null, includeDetails: boolean): Finding {
  if (!domain) {
    return {
      type: 'WEAK_PASSWORD_POLICY',
      severity: 'medium',
      category: 'advanced',
      title: 'Weak Password Policy',
      description: 'Unable to check domain password policy.',
      count: 0,
    };
  }

  const minPwdLength = (domain as any).minPwdLength || 0;
  const maxPwdAge = (domain as any).maxPwdAge || 0;
  const pwdHistoryLength = (domain as any).pwdHistoryLength || 0;

  const isWeak = minPwdLength < 14 || maxPwdAge > 90 || pwdHistoryLength < 24;

  return {
    type: 'WEAK_PASSWORD_POLICY',
    severity: 'medium',
    category: 'advanced',
    title: 'Weak Password Policy',
    description: 'Domain password policy below minimum standards. Enables easier password cracking.',
    count: isWeak ? 1 : 0,
    affectedEntities: includeDetails && isWeak ? [domain.dn] : undefined,
    details: isWeak
      ? {
          minPwdLength,
          maxPwdAge,
          pwdHistoryLength,
        }
      : undefined,
  };
}
