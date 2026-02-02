/**
 * ACL to Domain Admin Path Detector
 *
 * Detects ACL-based privilege escalation paths to Domain Admin.
 * Non-privileged users with write access chain to admin objects.
 */

import { ADUser, ADGroup, ADComputer, AclEntry } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';
import { toAffectedUserEntities } from '../../../../../../utils/entity-converter';
import { buildGroupMembershipGraph, buildAclGraph } from '../../../../../../utils/graph.util';

/**
 * Detect ACL-based privilege escalation paths to Domain Admin
 * Non-privileged users with write access chain to admin objects
 */
export function detectPathAclToDA(
  users: ADUser[],
  groups: ADGroup[],
  computers: ADComputer[],
  aclEntries: AclEntry[],
  includeDetails: boolean
): Finding {
  // Build combined graph
  const graph = buildGroupMembershipGraph(users, groups, computers);
  buildAclGraph(aclEntries, graph);

  // Find non-privileged users with paths to privileged targets
  const nonPrivilegedUsers = users.filter((u) => u.enabled && u.adminCount !== 1);

  const pathsFound: { user: ADUser; pathLength: number }[] = [];

  for (const user of nonPrivilegedUsers) {
    const path = graph.findShortestPathToPrivileged(user.dn, 4);
    if (path && path.edges.some((e) => e.type === 'canModify')) {
      pathsFound.push({ user, pathLength: path.length });
    }
  }

  // Sort by path length (shorter = more dangerous)
  pathsFound.sort((a, b) => a.pathLength - b.pathLength);
  const affected = pathsFound.map((p) => p.user);

  return {
    type: 'PATH_ACL_TO_DA',
    severity: 'critical',
    category: 'attack-paths',
    title: 'ACL-Based Privilege Escalation to Domain Admin',
    description:
      'Non-privileged users can escalate to Domain Admin through ACL chain (WriteDACL, GenericAll, WriteOwner).',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected.slice(0, 50)) : undefined,
    details:
      affected.length > 0
        ? {
            attackVector: 'Modify ACL → Take ownership → Add to DA group',
            shortestPath: pathsFound[0]?.pathLength,
            totalPaths: pathsFound.length,
            mitigation: 'Review and restrict dangerous ACL permissions',
          }
        : undefined,
  };
}
