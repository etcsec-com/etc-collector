/**
 * Weak DES Encryption Detector
 *
 * Detects user accounts with DES encryption algorithms enabled.
 * Checks both UAC flag 0x200000 (USE_DES_KEY_ONLY) and msDS-SupportedEncryptionTypes.
 * DES_CBC_CRC = 0x1, DES_CBC_MD5 = 0x2
 */

import { ADUser } from '../../../../../types/ad.types';
import { Finding } from '../../../../../types/finding.types';
import { toAffectedUserEntities } from '../../../../../utils/entity-converter';

/**
 * Check for weak DES encryption
 * Checks both UAC flag 0x200000 (USE_DES_KEY_ONLY) and msDS-SupportedEncryptionTypes
 * DES_CBC_CRC = 0x1, DES_CBC_MD5 = 0x2
 */
export function detectWeakEncryptionDES(users: ADUser[], includeDetails: boolean): Finding {
  const DES_TYPES = 0x3; // DES_CBC_CRC (0x1) | DES_CBC_MD5 (0x2)

  const affected = users.filter((u) => {
    // Check UAC flag USE_DES_KEY_ONLY
    if (u.userAccountControl && (u.userAccountControl & 0x200000) !== 0) {
      return true;
    }
    // Check msDS-SupportedEncryptionTypes for DES support
    const encTypes = (u as any)['msDS-SupportedEncryptionTypes'];
    if (typeof encTypes === 'number' && (encTypes & DES_TYPES) !== 0) {
      return true;
    }
    return false;
  });

  return {
    type: 'WEAK_ENCRYPTION_DES',
    severity: 'high',
    category: 'kerberos',
    title: 'Weak DES Encryption',
    description: 'User accounts with DES encryption algorithms enabled (UAC 0x200000 or msDS-SupportedEncryptionTypes). DES is cryptographically broken.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected) : undefined,
  };
}
