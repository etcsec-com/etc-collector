/**
 * Computer Takeover Path Detector
 *
 * Detects RBCD attack paths.
 * Computers with Resource-Based Constrained Delegation configured.
 */

import { ADUser, ADGroup, ADComputer } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';
import { buildGroupMembershipGraph } from '../../../../../../utils/graph.util';

/**
 * Detect RBCD attack paths
 * Computers with Resource-Based Constrained Delegation configured
 */
export function detectPathComputerTakeover(
  computers: ADComputer[],
  users: ADUser[],
  groups: ADGroup[],
  includeDetails: boolean
): Finding {
  const graph = buildGroupMembershipGraph(users, groups, computers);

  // Find computers with RBCD configured
  const rbcdComputers = computers.filter((c) => {
    const rbcd = (c as any)['msDS-AllowedToActOnBehalfOfOtherIdentity'];
    return rbcd && rbcd !== '';
  });

  // Check which are privileged (DCs, admin workstations)
  const dcPattern = /^(dc|domain controller)/i;
  const affected = rbcdComputers.filter((c) => {
    const computerMemberOf = c['memberOf'] as string[] | undefined;
    const isDC = dcPattern.test(c.sAMAccountName || '') || computerMemberOf?.some((g: string) => g.includes('Domain Controllers'));
    const isPrivileged = graph.isPrivileged(c.dn);
    return isDC || isPrivileged;
  });

  return {
    type: 'PATH_COMPUTER_TAKEOVER',
    severity: 'high',
    category: 'attack-paths',
    title: 'RBCD Computer Takeover Path',
    description:
      'Privileged computers have Resource-Based Constrained Delegation configured. Attackers controlling the delegating principal can compromise these computers.',
    count: affected.length,
    affectedEntities: includeDetails
      ? affected.map((c) => ({
          type: 'computer' as const,
          id: c.dn,
          displayName: c.sAMAccountName || c.dn,
          sAMAccountName: c.sAMAccountName,
          dNSHostName: c.dNSHostName || null,
          operatingSystem: c.operatingSystem || null,
          operatingSystemVersion: c.operatingSystemVersion || null,
          whenCreated: null,
          whenChanged: null,
          lastLogon: null,
          pwdLastSet: null,
          enabled: c.enabled ?? true,
          userAccountControl: 0,
        }))
      : undefined,
    details: {
      totalRbcdComputers: rbcdComputers.length,
      privilegedRbcdComputers: affected.length,
      attackVector: 'Control delegating account → RBCD → Impersonate on target',
      mitigation: 'Remove RBCD from privileged computers, monitor msDS-AllowedToActOnBehalfOfOtherIdentity',
    },
  };
}
