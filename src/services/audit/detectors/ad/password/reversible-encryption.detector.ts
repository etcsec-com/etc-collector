/**
 * Reversible Encryption Detector
 *
 * Detects user accounts with passwords stored using reversible encryption (UAC flag 0x80).
 * This is equivalent to storing passwords in cleartext.
 */

import { ADUser } from '../../../../../types/ad.types';
import { Finding } from '../../../../../types/finding.types';
import { toAffectedUserEntities } from '../../../../../utils/entity-converter';

/**
 * Check if password stored with reversible encryption (UAC flag 0x80)
 */
export function detectReversibleEncryption(users: ADUser[], includeDetails: boolean): Finding {
  const affected = users.filter((u) => {
    if (!u.userAccountControl) return false;
    return (u.userAccountControl & 0x80) !== 0; // ENCRYPTED_TEXT_PASSWORD_ALLOWED
  });

  return {
    type: 'REVERSIBLE_ENCRYPTION',
    severity: 'critical',
    category: 'passwords',
    title: 'Reversible Encryption',
    description: 'Passwords stored with reversible encryption (UAC flag 0x80). Equivalent to storing passwords in cleartext.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected) : undefined,
  };
}
