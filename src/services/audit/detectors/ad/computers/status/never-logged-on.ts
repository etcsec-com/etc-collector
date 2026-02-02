/**
 * Computer Never Logged On Detector
 * Check for computers that have never logged on
 * Enabled computers with no lastLogon date may indicate orphaned or unused accounts
 *
 * Checks both lastLogon (local to DC) and lastLogonTimestamp (replicated).
 */

import { ADComputer } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';
import { toAffectedComputerEntities } from '../../../../../../utils/entity-converter';
import { toTimestamp } from '../utils';

export function detectComputerNeverLoggedOn(
  computers: ADComputer[],
  includeDetails: boolean
): Finding {
  const affected = computers.filter((c) => {
    if (!c.enabled) return false;

    // Check both lastLogon and lastLogonTimestamp
    const lastLogonTime = toTimestamp(c.lastLogon) ?? toTimestamp((c as any)['lastLogonTimestamp']);

    // No logon time means never logged on
    return !lastLogonTime;
  });

  return {
    type: 'COMPUTER_NEVER_LOGGED_ON',
    severity: 'medium',
    category: 'computers',
    title: 'Computer Never Logged On',
    description:
      'Enabled computer accounts that have never authenticated to the domain. These may be orphaned accounts from failed deployments or unused systems that should be cleaned up.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedComputerEntities(affected) : undefined,
  };
}
