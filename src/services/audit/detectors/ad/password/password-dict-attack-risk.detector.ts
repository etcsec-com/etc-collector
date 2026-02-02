/**
 * Password Dictionary Attack Risk Detector
 *
 * Detects accounts that have been targeted by dictionary attacks
 * (multiple bad password attempts or lockouts).
 *
 * Phase 3 addition.
 */

import { ADUser } from '../../../../../types/ad.types';
import { Finding } from '../../../../../types/finding.types';
import { toAffectedUserEntities } from '../../../../../utils/entity-converter';

/**
 * Check for dictionary attack risk
 *
 * Accounts with low bad password count threshold allowing dictionary attacks.
 *
 * @param users - Array of AD users
 * @param includeDetails - Whether to include affected entity details
 * @returns Finding for PASSWORD_DICT_ATTACK_RISK
 */
export function detectPasswordDictAttackRisk(users: ADUser[], includeDetails: boolean): Finding {
  // Accounts that have been locked out or have high bad password count
  // This indicates they may have weak passwords being targeted
  const affected = users.filter((u) => {
    if (!u.enabled) return false;
    const badPwdCount = u.badPwdCount ?? 0;
    const lockoutTime = u.lockoutTime;

    // Account has been targeted (>3 bad password attempts) or is currently locked
    return badPwdCount > 3 || (lockoutTime && lockoutTime !== '0');
  });

  return {
    type: 'PASSWORD_DICT_ATTACK_RISK',
    severity: 'medium',
    category: 'passwords',
    title: 'Dictionary Attack Risk',
    description:
      'User accounts showing signs of password guessing attacks (multiple bad password attempts or lockouts). ' +
      'May indicate weak passwords being targeted or ongoing brute-force attacks.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected) : undefined,
    details: {
      recommendation:
        'Review affected accounts for weak passwords. Consider implementing Azure AD Password Protection.',
    },
  };
}
