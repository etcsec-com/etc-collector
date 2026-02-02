/**
 * OVERSIZED_GROUP - Groups with 100-500 members
 */

import { ADGroup } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';
import { toAffectedADGroupEntities } from '../../../../../../utils/entity-converter';

/**
 * Check for oversized groups (100-500 members)
 */
export function detectOversizedGroup(groups: ADGroup[], includeDetails: boolean): Finding {
  const affected = groups.filter((g) => {
    if (!g.member) return false;
    return g.member.length > 100 && g.member.length <= 500;
  });

  return {
    type: 'OVERSIZED_GROUP',
    severity: 'medium',
    category: 'groups',
    title: 'Oversized Group',
    description: 'Groups with 100-500 members. May indicate overly broad permissions.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedADGroupEntities(affected) : undefined,
  };
}
