/**
 * Weak RC4 Encryption Detector
 *
 * Detects user accounts supporting RC4 encryption without AES.
 * RC4 is deprecated and vulnerable to attacks.
 */

import { ADUser } from '../../../../../types/ad.types';
import { Finding } from '../../../../../types/finding.types';
import { toAffectedUserEntities } from '../../../../../utils/entity-converter';

/**
 * Check for RC4-only encryption (no AES)
 */
export function detectWeakEncryptionRC4(users: ADUser[], includeDetails: boolean): Finding {
  const affected = users.filter((u) => {
    const encTypes = (u as any)['msDS-SupportedEncryptionTypes'];
    if (typeof encTypes !== 'number') return false;
    return (encTypes & 4) !== 0 && (encTypes & 24) === 0;
  });

  return {
    type: 'WEAK_ENCRYPTION_RC4',
    severity: 'medium',
    category: 'kerberos',
    title: 'Weak RC4 Encryption',
    description: 'User accounts supporting RC4 encryption without AES. RC4 is deprecated and vulnerable to attacks.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected) : undefined,
  };
}
