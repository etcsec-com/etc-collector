/**
 * User Cannot Change Password Detector
 *
 * Detects user accounts forbidden from changing their own password (UAC flag 0x40).
 * Prevents password rotation.
 */

import { ADUser } from '../../../../../types/ad.types';
import { Finding } from '../../../../../types/finding.types';
import { toAffectedUserEntities } from '../../../../../utils/entity-converter';

/**
 * Check if user cannot change password (UAC flag 0x40)
 */
export function detectUserCannotChangePassword(users: ADUser[], includeDetails: boolean): Finding {
  const affected = users.filter((u) => {
    if (!u.userAccountControl) return false;
    return (u.userAccountControl & 0x40) !== 0; // PASSWD_CANT_CHANGE
  });

  return {
    type: 'USER_CANNOT_CHANGE_PASSWORD',
    severity: 'medium',
    category: 'passwords',
    title: 'User Cannot Change Password',
    description: 'User accounts forbidden from changing their own password (UAC flag 0x40). Prevents password rotation.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected) : undefined,
  };
}
