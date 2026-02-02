/**
 * Password Not Required Detector
 *
 * Detects user accounts that do not require a password (UAC flag 0x20).
 * Attackers can authenticate without credentials.
 */

import { ADUser } from '../../../../../types/ad.types';
import { Finding } from '../../../../../types/finding.types';
import { toAffectedUserEntities } from '../../../../../utils/entity-converter';

/**
 * Check if password is not required (UAC flag 0x20)
 */
export function detectPasswordNotRequired(users: ADUser[], includeDetails: boolean): Finding {
  const affected = users.filter((u) => {
    if (!u.userAccountControl) return false;
    return (u.userAccountControl & 0x20) !== 0; // PASSWD_NOTREQD
  });

  return {
    type: 'PASSWORD_NOT_REQUIRED',
    severity: 'critical',
    category: 'passwords',
    title: 'Password Not Required',
    description: 'User accounts that do not require a password (UAC flag 0x20). Attackers can authenticate without credentials.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected) : undefined,
  };
}
