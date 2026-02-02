/**
 * Computer Constrained Delegation Detector
 * Check for computer with constrained delegation
 */

import { ADComputer } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';
import { toAffectedComputerEntities } from '../../../../../../utils/entity-converter';

export function detectComputerConstrainedDelegation(
  computers: ADComputer[],
  includeDetails: boolean
): Finding {
  const affected = computers.filter((c) => {
    const delegateTo = (c as any)['msDS-AllowedToDelegateTo'];
    // Check that attribute exists, is not null, not empty string, and not empty array
    return delegateTo && (Array.isArray(delegateTo) ? delegateTo.length > 0 : delegateTo !== '');
  });

  return {
    type: 'COMPUTER_CONSTRAINED_DELEGATION',
    severity: 'critical',
    category: 'computers',
    title: 'Computer Constrained Delegation',
    description: 'Computer with constrained Kerberos delegation. Can impersonate users to specified services.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedComputerEntities(affected) : undefined,
  };
}
