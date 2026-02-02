/**
 * OVERSIZED_GROUP_CRITICAL - Groups with 500+ members
 */

import { ADGroup } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';
import { toAffectedADGroupEntities } from '../../../../../../utils/entity-converter';

/**
 * Check for oversized groups (500+ members)
 * PingCastle threshold: >500 members = critical
 */
export function detectOversizedGroupCritical(groups: ADGroup[], includeDetails: boolean): Finding {
  const affected = groups.filter((g) => {
    if (!g.member) return false;
    return g.member.length > 500;
  });

  return {
    type: 'OVERSIZED_GROUP_CRITICAL',
    severity: 'high',
    category: 'groups',
    title: 'Oversized Group (Critical)',
    description: 'Groups with 500+ members. Management/audit difficulty, excessive privileges, performance issues.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedADGroupEntities(affected) : undefined,
  };
}
