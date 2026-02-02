/**
 * Computer Pre-Created Detector
 * Check for pre-created computer accounts (disabled + never logged on)
 * These are staging accounts that were created but never used.
 * PingCastle: Computer_Pre_Created
 */

import { ADComputer } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';
import { toAffectedComputerEntities } from '../../../../../../utils/entity-converter';
import { toTimestamp } from '../utils';

export function detectComputerPreCreated(
  computers: ADComputer[],
  includeDetails: boolean
): Finding {
  const affected = computers.filter((c) => {
    // Disabled computer that has never logged on
    if (c.enabled) return false;

    // Check if it has never logged on
    const lastLogonTime = toTimestamp(c.lastLogon) ?? toTimestamp((c as any)['lastLogonTimestamp']);
    return !lastLogonTime;
  });

  return {
    type: 'COMPUTER_PRE_CREATED',
    severity: 'medium',
    category: 'computers',
    title: 'Computer Pre-Created (Staging)',
    description:
      'Disabled computer accounts that have never logged on. These are staging accounts that were created but never deployed. Should be reviewed and cleaned up.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedComputerEntities(affected) : undefined,
  };
}
