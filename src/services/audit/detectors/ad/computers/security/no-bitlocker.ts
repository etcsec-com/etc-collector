/**
 * Computer No BitLocker Detector
 * Detect computers without BitLocker encryption
 *
 * Computers without disk encryption are vulnerable to physical attacks
 * where hard drives can be removed and read.
 */

import { ADComputer } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';
import { toAffectedComputerEntities, ldapAttrToString } from '../../../../../../utils/entity-converter';

export function detectComputerNoBitlocker(
  computers: ADComputer[],
  includeDetails: boolean
): Finding {
  // BitLocker status is stored in ms-FVE-RecoveryInformation objects under the computer
  // We can check for msDS-isGC or look for recovery info attributes
  // For now, we check servers (not workstations) that likely need encryption
  const serversWithoutBitlocker = computers.filter((c) => {
    if (!c.enabled) return false;
    const os = ldapAttrToString(c.operatingSystem).toLowerCase();
    const isServer = os.includes('server');
    // Check if BitLocker recovery info exists (would need separate query)
    // For now, flag servers that might need BitLocker review
    const hasBitlockerInfo = (c as Record<string, unknown>)['ms-FVE-RecoveryInformation'] !== undefined;
    return isServer && !hasBitlockerInfo;
  });

  return {
    type: 'COMPUTER_NO_BITLOCKER',
    severity: 'high',
    category: 'computers',
    title: 'BitLocker Not Detected',
    description:
      'Servers without BitLocker recovery information in AD. ' +
      'Unencrypted disks are vulnerable to physical theft and offline attacks.',
    count: serversWithoutBitlocker.length,
    affectedEntities: includeDetails
      ? toAffectedComputerEntities(serversWithoutBitlocker)
      : undefined,
    details: {
      recommendation:
        'Enable BitLocker on all servers and configure AD backup of recovery keys.',
      note: 'This detection checks for ms-FVE-RecoveryInformation in AD. Standalone BitLocker may not be detected.',
    },
  };
}
