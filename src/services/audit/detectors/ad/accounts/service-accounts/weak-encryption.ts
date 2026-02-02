/**
 * Service Account Weak Encryption Detector
 * SERVICE_ACCOUNT_WEAK_ENCRYPTION: Service accounts using weak Kerberos encryption
 */

import { ADUser } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';
import { toAffectedUserEntities } from '../../../../../../utils/entity-converter';
import { isServiceAccount } from './utils';

export function detectServiceAccountWeakEncryption(users: ADUser[], includeDetails: boolean): Finding {
  // msDS-SupportedEncryptionTypes bit flags
  // 0x1 = DES-CBC-CRC, 0x2 = DES-CBC-MD5 (both weak)
  // 0x4 = RC4-HMAC (weak), 0x8 = AES128, 0x10 = AES256

  const affected = users.filter((u) => {
    // Must be a service account
    if (!isServiceAccount(u)) return false;
    // Must be enabled
    if (u.userAccountControl && (u.userAccountControl & 0x2) !== 0) return false;

    const encTypes = (u as any)['msDS-SupportedEncryptionTypes'];
    if (!encTypes) return false;

    const encTypesNum = typeof encTypes === 'string' ? parseInt(encTypes, 10) : encTypes;
    // Check if only weak encryption types are enabled (DES or RC4 only, no AES)
    const hasOnlyWeak = (encTypesNum & 0x7) !== 0 && (encTypesNum & 0x18) === 0;
    return hasOnlyWeak;
  });

  return {
    type: 'SERVICE_ACCOUNT_WEAK_ENCRYPTION',
    severity: 'medium',
    category: 'accounts',
    title: 'Service Account Using Weak Kerberos Encryption',
    description:
      'Service accounts configured to use only weak Kerberos encryption (DES/RC4) without AES. Makes offline cracking easier.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected) : undefined,
    details:
      affected.length > 0
        ? {
            recommendation: 'Enable AES128 and AES256 encryption for all service accounts.',
          }
        : undefined,
  };
}
