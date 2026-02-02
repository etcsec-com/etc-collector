/**
 * Computer Unconstrained Delegation Detector
 * Check for computer with unconstrained delegation
 */

import { ADComputer } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';
import { toAffectedComputerEntities } from '../../../../../../utils/entity-converter';

export function detectComputerUnconstrainedDelegation(
  computers: ADComputer[],
  includeDetails: boolean
): Finding {
  const affected = computers.filter((c) => {
    const uac = (c as any).userAccountControl;
    if (!uac) return false;
    return (uac & 0x80000) !== 0; // TRUSTED_FOR_DELEGATION
  });

  return {
    type: 'COMPUTER_UNCONSTRAINED_DELEGATION',
    severity: 'critical',
    category: 'computers',
    title: 'Computer Unconstrained Delegation',
    description: 'Computer with unconstrained delegation enabled. Servers can be used for privilege escalation attacks.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedComputerEntities(affected) : undefined,
  };
}
