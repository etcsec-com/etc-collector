/**
 * Computer Legacy Protocol Detector
 * Detect computers using legacy protocols
 *
 * Computers configured to use legacy/insecure protocols like SMBv1,
 * NTLMv1, or LM are vulnerable to various attacks.
 */

import { ADComputer } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';
import { toAffectedComputerEntities, ldapAttrToString } from '../../../../../../utils/entity-converter';

export function detectComputerLegacyProtocol(
  computers: ADComputer[],
  includeDetails: boolean
): Finding {
  // Check for computers with legacy OS that likely use legacy protocols
  const legacyOsPatterns = [
    /Windows XP/i,
    /Windows 2000/i,
    /Windows NT/i,
    /Server 2003/i,
    /Windows Vista/i,
  ];

  // Also check msDS-SupportedEncryptionTypes for weak encryption
  const affected = computers.filter((c) => {
    if (!c.enabled) return false;
    const os = ldapAttrToString(c.operatingSystem);

    // Legacy OS definitely uses legacy protocols
    const hasLegacyOs = legacyOsPatterns.some((p) => p.test(os));
    if (hasLegacyOs) return true;

    // Check supported encryption types (if only DES/RC4)
    const encTypes = (c as Record<string, unknown>)['msDS-SupportedEncryptionTypes'] as number | undefined;
    if (encTypes !== undefined) {
      // If only DES (0x1, 0x2) or RC4 (0x4) are supported, it's legacy
      const onlyLegacy = (encTypes & 0x18) === 0; // No AES128 (0x8) or AES256 (0x10)
      if (onlyLegacy && encTypes > 0) return true;
    }

    return false;
  });

  return {
    type: 'COMPUTER_LEGACY_PROTOCOL',
    severity: 'medium',
    category: 'computers',
    title: 'Legacy Protocol Support',
    description:
      'Computers configured to use legacy protocols (SMBv1, NTLMv1, DES/RC4 only). ' +
      'These are vulnerable to relay attacks, credential theft, and encryption downgrade.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedComputerEntities(affected) : undefined,
    details: {
      recommendation:
        'Upgrade legacy systems or disable legacy protocols. Enable AES encryption support.',
      protocols: ['SMBv1', 'NTLMv1', 'DES', 'RC4'],
    },
  };
}
