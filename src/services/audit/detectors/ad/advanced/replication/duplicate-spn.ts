/**
 * Duplicate SPN Detector
 * Check for duplicate SPNs
 */

import { ADUser } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';

export function detectDuplicateSpn(users: ADUser[], includeDetails: boolean): Finding {
  const spnMap = new Map<string, string[]>();

  // Build SPN to user DN mapping
  users.forEach((u) => {
    const spns = (u as any).servicePrincipalName;
    if (spns && Array.isArray(spns)) {
      spns.forEach((spn: string) => {
        if (!spnMap.has(spn)) {
          spnMap.set(spn, []);
        }
        spnMap.get(spn)!.push(u.dn);
      });
    }
  });

  // Find duplicate SPNs
  const affected: string[] = [];
  spnMap.forEach((dns, _spn) => {
    if (dns.length > 1) {
      affected.push(...dns);
    }
  });

  return {
    type: 'DUPLICATE_SPN',
    severity: 'medium',
    category: 'advanced',
    title: 'Duplicate SPN',
    description: 'Service Principal Name registered multiple times. Can cause Kerberos authentication failures.',
    count: affected.length,
    affectedEntities: includeDetails ? affected : undefined,
  };
}
