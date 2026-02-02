/**
 * LAPS Password Leaked Detector
 * Check for LAPS password leaked
 */

import { ADComputer } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';

export function detectLapsPasswordLeaked(computers: ADComputer[], includeDetails: boolean): Finding {
  const affected = computers.filter((c) => {
    return (c as any).lapsPasswordExcessiveReaders; // This would be populated by ACL analysis
  });

  return {
    type: 'LAPS_PASSWORD_LEAKED',
    severity: 'low',
    category: 'advanced',
    title: 'LAPS Password Leaked',
    description: 'LAPS password visible to too many users. Reduces effectiveness of LAPS.',
    count: affected.length,
    affectedEntities: includeDetails ? affected.map((c) => c.dn) : undefined,
  };
}
