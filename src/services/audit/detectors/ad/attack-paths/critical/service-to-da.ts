/**
 * Service Account to Domain Admin Path Detector
 *
 * Detects service accounts with path to Domain Admin.
 * Service accounts (SPN) that can reach DA through various vectors.
 */

import { ADUser, ADGroup, ADComputer, AclEntry } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';
import { toAffectedUserEntities } from '../../../../../../utils/entity-converter';
import {
  buildGroupMembershipGraph,
  buildAclGraph,
  addDelegationEdges,
} from '../../../../../../utils/graph.util';

/**
 * Detect service accounts with path to Domain Admin
 * Service accounts (SPN) that can reach DA through various vectors
 */
export function detectPathServiceToDA(
  users: ADUser[],
  groups: ADGroup[],
  computers: ADComputer[],
  aclEntries: AclEntry[],
  includeDetails: boolean
): Finding {
  const graph = buildGroupMembershipGraph(users, groups, computers);
  buildAclGraph(aclEntries, graph);
  addDelegationEdges(users, computers, graph);

  // Service accounts = users with SPNs
  const serviceAccounts = users.filter((u) => {
    const spn = u['servicePrincipalName'];
    const hasSPN = spn && Array.isArray(spn) && spn.length > 0;
    return hasSPN && u.enabled;
  });

  // Check which have any path to DA (membership, ACL, delegation)
  const affected = serviceAccounts.filter((sa) => {
    const path = graph.findShortestPathToPrivileged(sa.dn, 5);
    return path !== null;
  });

  return {
    type: 'PATH_SERVICE_TO_DA',
    severity: 'critical',
    category: 'attack-paths',
    title: 'Service Account Path to Domain Admin',
    description:
      'Service accounts with paths to Domain Admin through membership, ACLs, or delegation. Compromising these accounts leads to DA.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected) : undefined,
    details:
      affected.length > 0
        ? {
            totalServiceAccounts: serviceAccounts.length,
            withPathToDA: affected.length,
            attackVector: 'Kerberoast/Credential theft → Exploit path → Domain Admin',
            mitigation: 'Use gMSA, minimize service account privileges, regular password rotation',
          }
        : undefined,
  };
}
