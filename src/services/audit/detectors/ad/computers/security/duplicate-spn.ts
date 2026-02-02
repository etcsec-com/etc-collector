/**
 * Computer Duplicate SPN Detector
 * Detect duplicate SPNs across computers
 * Duplicate SPNs cause authentication failures
 */

import { ADComputer } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';
import { toAffectedComputerEntities } from '../../../../../../utils/entity-converter';

export function detectComputerDuplicateSpn(computers: ADComputer[], includeDetails: boolean): Finding {
  const spnMap = new Map<string, ADComputer[]>();

  // Build SPN to computer mapping
  for (const computer of computers) {
    const spns = computer['servicePrincipalName'];
    if (!spns || !Array.isArray(spns)) continue;

    for (const spn of spns) {
      const normalizedSpn = (spn as string).toLowerCase();
      if (!spnMap.has(normalizedSpn)) {
        spnMap.set(normalizedSpn, []);
      }
      spnMap.get(normalizedSpn)!.push(computer);
    }
  }

  // Find duplicates
  const duplicateComputers = new Set<ADComputer>();
  const duplicateSpns: { spn: string; computers: string[] }[] = [];

  for (const [spn, computersList] of spnMap.entries()) {
    if (computersList.length > 1) {
      duplicateSpns.push({
        spn,
        computers: computersList.map((c) => c.sAMAccountName || c.dn),
      });
      computersList.forEach((c) => duplicateComputers.add(c));
    }
  }

  return {
    type: 'COMPUTER_DUPLICATE_SPN',
    severity: 'medium',
    category: 'computers',
    title: 'Duplicate SPNs Detected',
    description:
      'Multiple computers share the same Service Principal Name. This causes Kerberos authentication failures.',
    count: duplicateComputers.size,
    affectedEntities: includeDetails ? toAffectedComputerEntities(Array.from(duplicateComputers)) : undefined,
    details:
      duplicateSpns.length > 0
        ? {
            duplicateSpns: duplicateSpns.slice(0, 10), // Show first 10
            totalDuplicates: duplicateSpns.length,
            recommendation:
              'Remove duplicate SPNs using setspn -D. Ensure each SPN is unique across the domain.',
          }
        : undefined,
  };
}
