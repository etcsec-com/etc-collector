/**
 * Kerberos RC4 Fallback Detector
 *
 * Detects accounts with RC4 fallback enabled.
 * While AES may be supported, RC4 fallback allows downgrade attacks.
 */

import { ADUser } from '../../../../../types/ad.types';
import { Finding } from '../../../../../types/finding.types';
import { toAffectedUserEntities } from '../../../../../utils/entity-converter';

/**
 * Detect accounts with RC4 fallback enabled
 *
 * While AES may be supported, RC4 fallback allows downgrade attacks.
 *
 * @param users - Array of AD users
 * @param includeDetails - Whether to include affected entity details
 * @returns Finding for KERBEROS_RC4_FALLBACK
 */
export function detectKerberosRc4Fallback(users: ADUser[], includeDetails: boolean): Finding {
  // RC4_HMAC_MD5 = 0x4
  const RC4_SUPPORT = 0x4;
  const AES_SUPPORT = 0x18;

  const affected = users.filter((u) => {
    if (!u.enabled) return false;
    const encTypes = (u as Record<string, unknown>)['msDS-SupportedEncryptionTypes'] as
      | number
      | undefined;
    if (encTypes === undefined) return false;
    // Has both AES and RC4 - RC4 should be disabled
    const hasAes = (encTypes & AES_SUPPORT) !== 0;
    const hasRc4 = (encTypes & RC4_SUPPORT) !== 0;
    return hasAes && hasRc4;
  });

  return {
    type: 'KERBEROS_RC4_FALLBACK',
    severity: 'medium',
    category: 'kerberos',
    title: 'RC4 Fallback Enabled',
    description:
      'User accounts support both AES and RC4 encryption. ' +
      'RC4 fallback enables downgrade attacks even when AES is available.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected) : undefined,
    details: {
      recommendation: 'Disable RC4 support when AES is available.',
    },
  };
}
