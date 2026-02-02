/**
 * Computer Admin Count Detector
 * Check for computer with adminCount attribute
 */

import { ADComputer } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';
import { toAffectedComputerEntities } from '../../../../../../utils/entity-converter';

export function detectComputerAdminCount(computers: ADComputer[], includeDetails: boolean): Finding {
  const affected = computers.filter((c) => {
    const adminCount = (c as any).adminCount;
    return adminCount === 1;
  });

  return {
    type: 'COMPUTER_ADMIN_COUNT',
    severity: 'low',
    category: 'computers',
    title: 'Computer adminCount Set',
    description: 'Computer with adminCount attribute set to 1. May indicate current or former administrative privileges.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedComputerEntities(affected) : undefined,
  };
}
