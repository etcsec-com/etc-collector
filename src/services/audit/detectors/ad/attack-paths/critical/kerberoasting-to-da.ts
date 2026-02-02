/**
 * Kerberoasting to Domain Admin Path Detector
 *
 * Detects kerberoastable users with path to Domain Admin.
 * Users with SPNs that are members (direct or nested) of privileged groups.
 */

import { ADUser, ADGroup, ADComputer } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';
import { toAffectedUserEntities } from '../../../../../../utils/entity-converter';
import { buildGroupMembershipGraph, isPrivilegedMember } from '../../../../../../utils/graph.util';

/**
 * Detect kerberoastable users with path to Domain Admin
 * Users with SPNs that are members (direct or nested) of privileged groups
 */
export function detectPathKerberoastingToDA(
  users: ADUser[],
  groups: ADGroup[],
  computers: ADComputer[],
  includeDetails: boolean
): Finding {
  const graph = buildGroupMembershipGraph(users, groups, computers);

  // Find kerberoastable users (have SPN and are enabled)
  const kerberoastableUsers = users.filter((u) => {
    const spn = u['servicePrincipalName'];
    const hasSPN = spn && Array.isArray(spn) && spn.length > 0;
    return hasSPN && u.enabled;
  });

  // Check which ones have path to privileged groups
  const affected = kerberoastableUsers.filter((u) => isPrivilegedMember(u.dn, graph));

  return {
    type: 'PATH_KERBEROASTING_TO_DA',
    severity: 'critical',
    category: 'attack-paths',
    title: 'Kerberoasting Path to Domain Admin',
    description:
      'User with SPN is member of privileged group. Kerberoasting this account and cracking the password leads to Domain Admin compromise.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected) : undefined,
    details:
      affected.length > 0
        ? {
            attackVector: 'Request TGS ticket → Offline crack → Domain Admin access',
            mitigation: 'Use gMSA for service accounts, remove from privileged groups, use long complex passwords',
          }
        : undefined,
  };
}
