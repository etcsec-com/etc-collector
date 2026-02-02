/**
 * Computer RBCD Detector
 * Check for computer with RBCD configured
 */

import { ADComputer } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';
import { toAffectedComputerEntities } from '../../../../../../utils/entity-converter';

export function detectComputerRbcd(computers: ADComputer[], includeDetails: boolean): Finding {
  const affected = computers.filter((c) => {
    const rbcdAttr = (c as any)['msDS-AllowedToActOnBehalfOfOtherIdentity'];
    // Check that attribute exists, is not null, not empty string, and not empty array
    return rbcdAttr && (Array.isArray(rbcdAttr) ? rbcdAttr.length > 0 : rbcdAttr !== '');
  });

  return {
    type: 'COMPUTER_RBCD',
    severity: 'critical',
    category: 'computers',
    title: 'Computer RBCD',
    description: 'Computer with Resource-Based Constrained Delegation. Enables privilege escalation via RBCD attack.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedComputerEntities(affected) : undefined,
  };
}
