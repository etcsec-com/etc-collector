/**
 * Password Never Expires Detector
 *
 * Detects user accounts with passwords set to never expire (UAC flag 0x10000).
 * Old passwords increase breach risk.
 */

import { ADUser } from '../../../../../types/ad.types';
import { Finding } from '../../../../../types/finding.types';
import { toAffectedUserEntities } from '../../../../../utils/entity-converter';

/**
 * Check if password never expires (UAC flag 0x10000)
 */
export function detectPasswordNeverExpires(users: ADUser[], includeDetails: boolean): Finding {
  const affected = users.filter((u) => {
    if (!u.userAccountControl) return false;
    return (u.userAccountControl & 0x10000) !== 0; // DONT_EXPIRE_PASSWD
  });

  return {
    type: 'PASSWORD_NEVER_EXPIRES',
    severity: 'critical',
    category: 'passwords',
    title: 'Password Never Expires',
    description: 'User accounts with passwords set to never expire (UAC flag 0x10000). Old passwords increase breach risk.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected) : undefined,
  };
}
