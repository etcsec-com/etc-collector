/**
 * AS-REP Roasting to Admin Path Detector
 *
 * Detects AS-REP roastable users with path to admin groups.
 * Users without Kerberos pre-auth that are in admin groups.
 */

import { ADUser, ADGroup, ADComputer } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';
import { toAffectedUserEntities } from '../../../../../../utils/entity-converter';
import { buildGroupMembershipGraph, isPrivilegedMember } from '../../../../../../utils/graph.util';

/**
 * Detect AS-REP roastable users with path to admin groups
 * Users without Kerberos pre-auth that are in admin groups
 */
export function detectPathAsrepToAdmin(
  users: ADUser[],
  groups: ADGroup[],
  computers: ADComputer[],
  includeDetails: boolean
): Finding {
  const graph = buildGroupMembershipGraph(users, groups, computers);

  // Find AS-REP roastable users (DONT_REQUIRE_PREAUTH flag)
  const asrepUsers = users.filter((u) => {
    const hasNoPreauth = u.userAccountControl ? (u.userAccountControl & 0x400000) !== 0 : false;
    return hasNoPreauth && u.enabled;
  });

  // Check which ones have path to privileged groups
  const affected = asrepUsers.filter((u) => isPrivilegedMember(u.dn, graph));

  return {
    type: 'PATH_ASREP_TO_ADMIN',
    severity: 'high',
    category: 'attack-paths',
    title: 'AS-REP Roasting Path to Admin',
    description:
      'User without Kerberos pre-authentication is member of admin group. AS-REP roasting can lead to admin compromise.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected) : undefined,
    details:
      affected.length > 0
        ? {
            attackVector: 'Request AS-REP → Offline crack → Admin access',
            mitigation: 'Enable Kerberos pre-authentication, remove from admin groups',
          }
        : undefined,
  };
}
