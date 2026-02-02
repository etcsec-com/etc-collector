/**
 * LAPS Not Deployed Detector
 * Check for LAPS not deployed
 */

import { ADComputer } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';

export function detectLapsNotDeployed(computers: ADComputer[], includeDetails: boolean): Finding {
  const affected = computers.filter((c) => {
    return !('ms-Mcs-AdmPwd' in c) && !('msLAPS-Password' in c);
  });

  return {
    type: 'LAPS_NOT_DEPLOYED',
    severity: 'medium',
    category: 'advanced',
    title: 'LAPS Not Deployed',
    description: 'LAPS not deployed on domain computers. Shared/static local admin passwords across workstations.',
    count: affected.length,
    affectedEntities: includeDetails ? affected.map((c) => c.dn) : undefined,
  };
}
