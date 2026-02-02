/**
 * OVERSIZED_GROUP_HIGH - Groups with 200-500 members
 */

import { ADGroup } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';
import { toAffectedADGroupEntities } from '../../../../../../utils/entity-converter';

/**
 * Check for oversized groups (200-500 members)
 */
export function detectOversizedGroupHigh(groups: ADGroup[], includeDetails: boolean): Finding {
  const affected = groups.filter((g) => {
    if (!g.member) return false;
    return g.member.length > 200 && g.member.length <= 500;
  });

  return {
    type: 'OVERSIZED_GROUP_HIGH',
    severity: 'medium',
    category: 'groups',
    title: 'Oversized Group (High)',
    description: 'Groups with 200-500 members. Management difficulty and potential privilege creep.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedADGroupEntities(affected) : undefined,
  };
}
