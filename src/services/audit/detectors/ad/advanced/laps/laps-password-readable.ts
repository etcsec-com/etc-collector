/**
 * LAPS Password Readable Detector
 * Check for LAPS password readable by non-admins
 */

import { ADComputer } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';

export function detectLapsPasswordReadable(computers: ADComputer[], includeDetails: boolean): Finding {
  const affected = computers.filter((c) => {
    return (c as any).lapsPasswordReadableByNonAdmins; // This would be populated by ACL analysis
  });

  return {
    type: 'LAPS_PASSWORD_READABLE',
    severity: 'high',
    category: 'advanced',
    title: 'LAPS Password Readable',
    description: 'Non-admin users can read LAPS password attributes. Exposure of local admin passwords.',
    count: affected.length,
    affectedEntities: includeDetails ? affected.map((c) => c.dn) : undefined,
  };
}
