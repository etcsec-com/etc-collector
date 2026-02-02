/**
 * Computer DCSync Rights Detector
 * Check for computer with DCSync rights
 */

import { ADComputer } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';
import { toAffectedComputerEntities } from '../../../../../../utils/entity-converter';

export function detectComputerDcsyncRights(computers: ADComputer[], includeDetails: boolean): Finding {
  // Note: This requires ACL analysis which would be done in permissions detector
  // For now, we detect computers with the replication rights attribute
  const affected = computers.filter((c) => {
    return 'replicationRights' in c && (c as any).replicationRights;
  });

  return {
    type: 'COMPUTER_DCSYNC_RIGHTS',
    severity: 'critical',
    category: 'computers',
    title: 'Computer DCSync Rights',
    description: 'Computer with DCSync replication rights. Can extract all domain password hashes.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedComputerEntities(affected) : undefined,
  };
}
