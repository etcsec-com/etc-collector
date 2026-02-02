/**
 * Computer Pre-Windows 2000 Detector
 * Check for Pre-Windows 2000 computer accounts
 */

import { ADComputer } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';
import { toAffectedComputerEntities, ldapAttrToString } from '../../../../../../utils/entity-converter';

export function detectComputerPreWindows2000(computers: ADComputer[], includeDetails: boolean): Finding {
  const affected = computers.filter((c) => {
    const os = ldapAttrToString(c.operatingSystem);
    if (!os) return false;
    return /Windows NT|Windows 2000|Windows 95|Windows 98/i.test(os);
  });

  return {
    type: 'COMPUTER_PRE_WINDOWS_2000',
    severity: 'medium',
    category: 'computers',
    title: 'Pre-Windows 2000 Computer',
    description: 'Pre-Windows 2000 compatible computer. Weak security settings, potential compatibility exploits.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedComputerEntities(affected) : undefined,
  };
}
