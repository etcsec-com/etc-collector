/**
 * LAPS Legacy Attribute Detector
 * Check for legacy LAPS attribute
 */

import { ADComputer } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';

export function detectLapsLegacyAttribute(computers: ADComputer[], includeDetails: boolean): Finding {
  const affected = computers.filter((c) => {
    return 'ms-Mcs-AdmPwd' in c && !('msLAPS-Password' in c);
  });

  return {
    type: 'LAPS_LEGACY_ATTRIBUTE',
    severity: 'medium',
    category: 'advanced',
    title: 'LAPS Legacy Attribute',
    description: 'Legacy LAPS attribute used instead of Windows LAPS. Less secure implementation.',
    count: affected.length,
    affectedEntities: includeDetails ? affected.map((c) => c.dn) : undefined,
  };
}
