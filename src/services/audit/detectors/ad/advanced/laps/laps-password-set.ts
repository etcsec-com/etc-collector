/**
 * LAPS Password Set Detector
 * Check for LAPS password set (informational)
 */

import { ADComputer } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';

export function detectLapsPasswordSet(computers: ADComputer[], includeDetails: boolean): Finding {
  const affected = computers.filter((c) => {
    return 'ms-Mcs-AdmPwd' in c || 'msLAPS-Password' in c;
  });

  return {
    type: 'LAPS_PASSWORD_SET',
    severity: 'low',
    category: 'advanced',
    title: 'LAPS Password Set',
    description: 'LAPS password successfully managed. Informational - indicates proper LAPS deployment.',
    count: affected.length,
    affectedEntities: includeDetails ? affected.map((c) => c.dn) : undefined,
  };
}
