/**
 * TRUST_RC4_ONLY Detector
 * Trust only supports RC4 encryption - RC4 is deprecated and vulnerable to offline attacks
 */

import { Finding } from '../../../../../types/finding.types';
import { ADTrustExtended } from '../../../../../types/trust.types';
import { ENC_AES_TYPES, ENC_TYPE_RC4_HMAC, ENC_WEAK_ONLY } from './utils';

export function detectTrustRc4Only(
  trusts: ADTrustExtended[],
  includeDetails: boolean
): Finding {
  const affected = trusts.filter((t) => {
    // Skip if encryption types not available
    if (t.supportedEncryptionTypes === undefined) return false;
    // Check if ONLY weak encryption is supported (RC4/DES only, no AES)
    const hasOnlyWeak =
      (t.supportedEncryptionTypes & ENC_WEAK_ONLY) !== 0 &&
      (t.supportedEncryptionTypes & ENC_AES_TYPES) === 0;
    // Specifically RC4 only (not DES)
    const isRc4Only =
      hasOnlyWeak && (t.supportedEncryptionTypes & ENC_TYPE_RC4_HMAC) !== 0;
    return isRc4Only;
  });

  return {
    type: 'TRUST_RC4_ONLY',
    severity: 'high',
    category: 'trusts',
    title: 'Trust Only Supports RC4 Encryption',
    description:
      'Trust relationship only supports RC4 encryption (no AES). RC4 is deprecated and Kerberos tickets encrypted with RC4 are vulnerable to offline cracking attacks.',
    count: affected.length,
    affectedEntities: includeDetails ? affected.map((t) => t.name) : undefined,
    details:
      affected.length > 0
        ? {
            recommendation:
              'Enable AES encryption on trust. If the partner domain does not support AES, plan an upgrade path.',
          }
        : undefined,
  };
}
