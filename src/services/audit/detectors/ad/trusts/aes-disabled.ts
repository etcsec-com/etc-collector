/**
 * TRUST_AES_DISABLED Detector
 * AES encryption not enabled on trust - forces use of weaker encryption algorithms
 */

import { Finding } from '../../../../../types/finding.types';
import { ADTrustExtended } from '../../../../../types/trust.types';
import { ENC_AES_TYPES } from './utils';

export function detectTrustAesDisabled(
  trusts: ADTrustExtended[],
  includeDetails: boolean
): Finding {
  const affected = trusts.filter((t) => {
    // Skip if encryption types not available
    if (t.supportedEncryptionTypes === undefined) return false;
    // Check if AES is NOT supported (neither AES128 nor AES256)
    return (t.supportedEncryptionTypes & ENC_AES_TYPES) === 0;
  });

  return {
    type: 'TRUST_AES_DISABLED',
    severity: 'high',
    category: 'trusts',
    title: 'AES Encryption Disabled on Trust',
    description:
      'Trust relationship does not support AES encryption. This forces the use of weaker encryption algorithms (RC4/DES) which are more vulnerable to offline cracking.',
    count: affected.length,
    affectedEntities: includeDetails ? affected.map((t) => t.name) : undefined,
    details:
      affected.length > 0
        ? {
            recommendation:
              'Enable AES128 and AES256 encryption on trust relationship. Ensure both domains support AES.',
          }
        : undefined,
  };
}
