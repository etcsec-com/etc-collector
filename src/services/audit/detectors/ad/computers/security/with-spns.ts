/**
 * Computer with SPNs Detector
 * Check for computer with SPNs (Kerberoastable)
 */

import { ADComputer } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';
import { toAffectedComputerEntities } from '../../../../../../utils/entity-converter';

export function detectComputerWithSpns(computers: ADComputer[], includeDetails: boolean): Finding {
  const affected = computers.filter((c) => {
    const spns = (c as any).servicePrincipalName;
    return spns && spns.length > 0;
  });

  return {
    type: 'COMPUTER_WITH_SPNS',
    severity: 'high',
    category: 'computers',
    title: 'Computer with SPNs',
    description: 'Computer with Service Principal Names. Enables Kerberoasting attack against computer account.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedComputerEntities(affected) : undefined,
  };
}
