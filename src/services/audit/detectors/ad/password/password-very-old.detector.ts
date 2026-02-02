/**
 * Password Very Old Detector
 *
 * Detects user accounts with passwords older than 365 days.
 * Increases risk of credential compromise.
 */

import { ADUser } from '../../../../../types/ad.types';
import { Finding } from '../../../../../types/finding.types';
import { toAffectedUserEntities } from '../../../../../utils/entity-converter';

/**
 * Check if password is very old (>365 days)
 */
export function detectPasswordVeryOld(users: ADUser[], includeDetails: boolean): Finding {
  const now = Date.now();
  const oneYearAgo = now - 365 * 24 * 60 * 60 * 1000;

  const affected = users.filter((u) => {
    if (!u.passwordLastSet) return false;
    return u.passwordLastSet.getTime() < oneYearAgo;
  });

  return {
    type: 'PASSWORD_VERY_OLD',
    severity: 'medium',
    category: 'passwords',
    title: 'Password Very Old',
    description: 'User accounts with passwords older than 365 days. Increases risk of credential compromise.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected) : undefined,
  };
}
