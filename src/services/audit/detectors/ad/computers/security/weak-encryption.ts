/**
 * Computer Weak Encryption Detector
 * Check for computer with weak encryption (DES/RC4 only)
 */

import { ADComputer } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';
import { toAffectedComputerEntities } from '../../../../../../utils/entity-converter';

export function detectComputerWeakEncryption(computers: ADComputer[], includeDetails: boolean): Finding {
  const affected = computers.filter((c) => {
    const encTypes = (c as any)['msDS-SupportedEncryptionTypes'];
    if (typeof encTypes !== 'number') return false;
    // Check if only DES/RC4 (no AES)
    return (encTypes & 0x18) === 0 && (encTypes & 0x7) !== 0;
  });

  return {
    type: 'COMPUTER_WEAK_ENCRYPTION',
    severity: 'medium',
    category: 'computers',
    title: 'Computer Weak Encryption',
    description: 'Computer with weak encryption types (DES/RC4 only). Vulnerable to Kerberos downgrade attacks.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedComputerEntities(affected) : undefined,
  };
}
