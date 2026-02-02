/**
 * Kerberos AES Disabled Detector
 *
 * Detects accounts with AES encryption disabled.
 * Accounts without AES support are limited to weaker DES/RC4 encryption,
 * making them vulnerable to offline cracking attacks.
 */

import { ADUser } from '../../../../../types/ad.types';
import { Finding } from '../../../../../types/finding.types';
import { toAffectedUserEntities } from '../../../../../utils/entity-converter';

/**
 * Detect accounts with AES encryption disabled
 *
 * Accounts without AES support are limited to weaker DES/RC4 encryption,
 * making them vulnerable to offline cracking attacks.
 *
 * @param users - Array of AD users
 * @param includeDetails - Whether to include affected entity details
 * @returns Finding for KERBEROS_AES_DISABLED
 */
export function detectKerberosAesDisabled(users: ADUser[], includeDetails: boolean): Finding {
  // msDS-SupportedEncryptionTypes: AES128=0x8, AES256=0x10
  const AES_SUPPORT = 0x18;

  const affected = users.filter((u) => {
    if (!u.enabled) return false;
    const encTypes = (u as Record<string, unknown>)['msDS-SupportedEncryptionTypes'] as
      | number
      | undefined;
    // If explicitly set and doesn't include AES
    if (encTypes !== undefined && (encTypes & AES_SUPPORT) === 0) {
      return true;
    }
    // If UAC indicates DES-only (0x200000 = USE_DES_KEY_ONLY)
    if (u.userAccountControl && (u.userAccountControl & 0x200000) !== 0) {
      return true;
    }
    return false;
  });

  return {
    type: 'KERBEROS_AES_DISABLED',
    severity: 'high',
    category: 'kerberos',
    title: 'AES Encryption Disabled',
    description:
      'User accounts with AES Kerberos encryption disabled. ' +
      'Forces use of weaker DES/RC4 encryption vulnerable to offline attacks.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected) : undefined,
  };
}
