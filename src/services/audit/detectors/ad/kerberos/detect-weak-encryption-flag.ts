/**
 * Weak Encryption Flag Detector
 *
 * Detects user accounts with USE_DES_KEY_ONLY flag enabled.
 * UAC flag 0x200000 forces weak DES encryption.
 */

import { ADUser } from '../../../../../types/ad.types';
import { Finding } from '../../../../../types/finding.types';
import { toAffectedUserEntities } from '../../../../../utils/entity-converter';

/**
 * Check for USE_DES_KEY_ONLY flag
 */
export function detectWeakEncryptionFlag(users: ADUser[], includeDetails: boolean): Finding {
  const affected = users.filter((u) => {
    if (!u.userAccountControl) return false;
    return (u.userAccountControl & 0x200000) !== 0;
  });

  return {
    type: 'WEAK_ENCRYPTION_FLAG',
    severity: 'medium',
    category: 'kerberos',
    title: 'Weak Encryption Flag',
    description: 'User accounts with USE_DES_KEY_ONLY flag enabled (UAC 0x200000). Forces weak DES encryption.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected) : undefined,
  };
}
