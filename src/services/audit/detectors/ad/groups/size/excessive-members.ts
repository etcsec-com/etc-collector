/**
 * GROUP_EXCESSIVE_MEMBERS - Groups with excessive direct members
 */

import { ADGroup } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';
import { toAffectedADGroupEntities } from '../../../../../../utils/entity-converter';

/**
 * Detect groups with excessive direct members
 * Large groups are difficult to manage and review
 */
export function detectGroupExcessiveMembers(groups: ADGroup[], includeDetails: boolean): Finding {
  const EXCESSIVE_THRESHOLD = 100;

  const affected = groups.filter((g) => {
    const memberCount = g.member?.length ?? 0;
    return memberCount > EXCESSIVE_THRESHOLD;
  });

  // Sort by member count (most members first)
  affected.sort((a, b) => (b.member?.length ?? 0) - (a.member?.length ?? 0));

  return {
    type: 'GROUP_EXCESSIVE_MEMBERS',
    severity: 'medium',
    category: 'groups',
    title: 'Group with Excessive Members',
    description: `Groups with more than ${EXCESSIVE_THRESHOLD} direct members. Large groups are difficult to audit and may grant unintended access.`,
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedADGroupEntities(affected) : undefined,
    details:
      affected.length > 0
        ? {
            threshold: EXCESSIVE_THRESHOLD,
            largestGroups: affected.slice(0, 5).map((g) => ({
              name: g.sAMAccountName || g.dn,
              memberCount: g.member?.length ?? 0,
            })),
            recommendation:
              'Review large groups and consider breaking into smaller, role-based groups for better access control.',
          }
        : undefined,
  };
}
