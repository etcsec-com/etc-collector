/**
 * Nested Admin Path Detector
 *
 * Detects excessive group nesting leading to admin access.
 * Groups nested more than 3 levels deep reaching admin groups.
 */

import { ADUser, ADGroup } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';
import { toAffectedUserEntities } from '../../../../../../utils/entity-converter';
import { detectNestingDepth, PRIVILEGED_GROUPS } from '../../../../../../utils/graph.util';

/**
 * Detect excessive group nesting leading to admin access
 * Groups nested more than 3 levels deep reaching admin groups
 */
export function detectPathNestedAdmin(
  users: ADUser[],
  groups: ADGroup[],
  includeDetails: boolean
): Finding {
  const EXCESSIVE_DEPTH = 3;

  // Find privileged groups
  const privilegedGroupDns = groups
    .filter((g) =>
      PRIVILEGED_GROUPS.some(
        (pg) =>
          g.sAMAccountName?.toLowerCase().includes(pg.toLowerCase()) ||
          g.dn.toLowerCase().includes(`cn=${pg.toLowerCase()}`)
      )
    )
    .map((g) => g.dn);

  // Find users in deeply nested paths to admin
  const affected: ADUser[] = [];
  const deepNestingDetails: { user: string; depth: number; group: string }[] = [];

  for (const user of users) {
    if (!user.memberOf || user.memberOf.length === 0) continue;

    for (const groupDn of user.memberOf) {
      const depth = detectNestingDepth(groupDn, groups);

      // Check if this chain reaches a privileged group
      if (depth > EXCESSIVE_DEPTH) {
        // Check if any parent in chain is privileged
        const group = groups.find((g) => g.dn.toLowerCase() === groupDn.toLowerCase());
        if (group?.memberOf?.some((parent) => privilegedGroupDns.includes(parent))) {
          affected.push(user);
          deepNestingDetails.push({
            user: user.sAMAccountName,
            depth,
            group: groupDn,
          });
          break;
        }
      }
    }
  }

  return {
    type: 'PATH_NESTED_ADMIN',
    severity: 'high',
    category: 'attack-paths',
    title: 'Excessive Group Nesting to Admin',
    description: `Users reach admin groups through excessive nesting (>${EXCESSIVE_DEPTH} levels). Makes privilege review difficult and may hide admin access.`,
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected) : undefined,
    details:
      affected.length > 0
        ? {
            threshold: EXCESSIVE_DEPTH,
            deepestNesting: Math.max(...deepNestingDetails.map((d) => d.depth), 0),
            mitigation: 'Flatten group structure, limit nesting to 2-3 levels',
          }
        : undefined,
  };
}
