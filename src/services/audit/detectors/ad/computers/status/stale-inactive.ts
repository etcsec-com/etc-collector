/**
 * Computer Stale/Inactive Detector
 * Check for stale/inactive computers (90+ days)
 * Note: Computers that have NEVER logged on are handled by COMPUTER_NEVER_LOGGED_ON
 */

import { ADComputer } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';
import { toAffectedComputerEntities } from '../../../../../../utils/entity-converter';
import { toTimestamp } from '../utils';

export function detectComputerStaleInactive(computers: ADComputer[], includeDetails: boolean): Finding {
  const now = Date.now();
  const ninetyDaysAgo = now - 90 * 24 * 60 * 60 * 1000;

  const affected = computers.filter((c) => {
    // Only check enabled computers
    if (!c.enabled) return false;

    // Try lastLogon first, then lastLogonTimestamp (replicated, more reliable)
    const lastLogonTime =
      toTimestamp(c.lastLogon) ?? toTimestamp((c as any)['lastLogonTimestamp']);

    // Skip if no logon time (handled by COMPUTER_NEVER_LOGGED_ON)
    if (!lastLogonTime) return false;

    return lastLogonTime < ninetyDaysAgo;
  });

  return {
    type: 'COMPUTER_STALE_INACTIVE',
    severity: 'high',
    category: 'computers',
    title: 'Computer Stale/Inactive',
    description: 'Computer inactive for 90+ days. Orphaned computer accounts could be exploited without detection.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedComputerEntities(affected) : undefined,
  };
}
