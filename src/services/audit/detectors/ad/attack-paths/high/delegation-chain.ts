/**
 * Delegation Chain Path Detector
 *
 * Detects delegation chains to privileged targets.
 * Users/computers with constrained delegation to privileged services.
 */

import { ADUser, ADGroup, ADComputer } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';
import { toAffectedUserEntities } from '../../../../../../utils/entity-converter';
import { buildGroupMembershipGraph, addDelegationEdges } from '../../../../../../utils/graph.util';

/**
 * Detect delegation chains to privileged targets
 * Users/computers with constrained delegation to privileged services
 */
export function detectPathDelegationChain(
  users: ADUser[],
  computers: ADComputer[],
  groups: ADGroup[],
  includeDetails: boolean
): Finding {
  const graph = buildGroupMembershipGraph(users, groups, computers);
  addDelegationEdges(users, computers, graph);

  // Find users with delegation rights
  const usersWithDelegation = users.filter((u) => {
    const allowedTo = (u as any)['msDS-AllowedToDelegateTo'];
    return allowedTo && Array.isArray(allowedTo) && allowedTo.length > 0;
  });

  // Find computers with delegation rights
  const computersWithDelegation = computers.filter((c) => {
    const allowedTo = (c as any)['msDS-AllowedToDelegateTo'];
    return allowedTo && Array.isArray(allowedTo) && allowedTo.length > 0;
  });

  // Check if delegation targets include privileged services (DC services, admin workstations)
  const dcServicePatterns = ['ldap/', 'cifs/', 'host/', 'krbtgt/'];
  const affectedUsers: ADUser[] = [];

  for (const user of usersWithDelegation) {
    const targets = (user as any)['msDS-AllowedToDelegateTo'] as string[];
    const hasDCTarget = targets.some((t) =>
      dcServicePatterns.some((p) => t.toLowerCase().startsWith(p.toLowerCase()))
    );
    if (hasDCTarget) {
      affectedUsers.push(user);
    }
  }

  return {
    type: 'PATH_DELEGATION_CHAIN',
    severity: 'high',
    category: 'attack-paths',
    title: 'Delegation Chain to Privileged Target',
    description:
      'Accounts with constrained delegation to domain controller services. Can be exploited to impersonate privileged users.',
    count: affectedUsers.length + computersWithDelegation.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affectedUsers) : undefined,
    details: {
      usersWithDelegation: usersWithDelegation.length,
      computersWithDelegation: computersWithDelegation.length,
      attackVector: 'Request S4U2Self → S4U2Proxy to DC service → Impersonate DA',
      mitigation: 'Remove unnecessary delegation, use Protected Users group',
    },
  };
}
