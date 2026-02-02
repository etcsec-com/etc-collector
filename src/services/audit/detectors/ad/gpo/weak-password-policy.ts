/**
 * GPO_WEAK_PASSWORD_POLICY - GPO with weak password settings
 */

import { Finding } from '../../../../../types/finding.types';
import { ADGPO, GPOLink } from '../../../../../types/gpo.types';

/**
 * GPO_WEAK_PASSWORD_POLICY: GPO with weak password settings
 * Note: Requires reading GptTmpl.inf via SMB - check domain policy instead
 */
export function detectGpoWeakPasswordPolicy(
  _gpos: ADGPO[],
  _links: GPOLink[],
  domainPasswordPolicy: { minPasswordLength?: number } | null,
  includeDetails: boolean
): Finding {
  const minLength = domainPasswordPolicy?.minPasswordLength ?? 0;
  const isWeak = minLength < 12;

  return {
    type: 'GPO_WEAK_PASSWORD_POLICY',
    severity: 'medium',
    category: 'gpo',
    title: 'Weak Password Policy',
    description: `Domain password policy requires only ${minLength} characters minimum. Microsoft recommends at least 12 characters for standard accounts, 14+ for privileged accounts.`,
    count: isWeak ? 1 : 0,
    affectedEntities: includeDetails && isWeak ? ['Default Domain Policy'] : undefined,
    details: isWeak
      ? {
          currentMinLength: minLength,
          recommendedMinLength: 12,
        }
      : undefined,
  };
}
