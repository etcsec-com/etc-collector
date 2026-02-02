/**
 * GROUP_CIRCULAR_NESTING - Circular group membership references
 */

import { ADGroup } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';
import { toAffectedADGroupEntities } from '../../../../../../utils/entity-converter';

/**
 * Detect circular group nesting
 * Groups that are members of each other create infinite loops
 */
export function detectGroupCircularNesting(groups: ADGroup[], includeDetails: boolean): Finding {
  const groupDnMap = new Map<string, ADGroup>();
  for (const g of groups) {
    groupDnMap.set(g.dn.toLowerCase(), g);
  }

  const circularGroups: ADGroup[] = [];
  const visited = new Set<string>();

  const detectCycle = (groupDn: string, path: Set<string>): boolean => {
    const normalizedDn = groupDn.toLowerCase();
    if (path.has(normalizedDn)) return true; // Cycle detected
    if (visited.has(normalizedDn)) return false; // Already checked, no cycle

    visited.add(normalizedDn);
    path.add(normalizedDn);

    const group = groupDnMap.get(normalizedDn);
    if (group?.memberOf) {
      for (const parentDn of group.memberOf) {
        if (groupDnMap.has(parentDn.toLowerCase())) {
          if (detectCycle(parentDn, path)) {
            return true;
          }
        }
      }
    }

    path.delete(normalizedDn);
    return false;
  };

  for (const group of groups) {
    visited.clear();
    if (detectCycle(group.dn, new Set())) {
      circularGroups.push(group);
    }
  }

  return {
    type: 'GROUP_CIRCULAR_NESTING',
    severity: 'medium',
    category: 'groups',
    title: 'Circular Group Nesting',
    description:
      'Groups contain circular membership references. This can cause authentication issues and makes privilege analysis unreliable.',
    count: circularGroups.length,
    affectedEntities: includeDetails ? toAffectedADGroupEntities(circularGroups) : undefined,
    details:
      circularGroups.length > 0
        ? {
            recommendation: 'Remove circular nesting by reviewing and restructuring group membership.',
            impact: 'May cause token bloat, authentication failures, and unreliable access control.',
          }
        : undefined,
  };
}
