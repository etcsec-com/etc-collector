/**
 * Attack Paths Vulnerability Detector
 *
 * Analyzes privilege escalation paths in Active Directory by combining:
 * - Group membership chains
 * - ACL-based attack vectors
 * - Delegation relationships
 * - Service account risks
 *
 * Phase 2: Attack Paths Detection
 *
 * Vulnerabilities detected (10):
 * CRITICAL (4):
 * - PATH_KERBEROASTING_TO_DA: Kerberoastable user in DA path
 * - PATH_ACL_TO_DA: ACL chain to Domain Admin
 * - PATH_SERVICE_TO_DA: Service account with path to DA
 * - PATH_CERTIFICATE_ESC: ADCS template vulnerability to DA
 *
 * HIGH (5):
 * - PATH_ASREP_TO_ADMIN: AS-REP roastable user in admin group
 * - PATH_DELEGATION_CHAIN: Delegation chain to privileged target
 * - PATH_NESTED_ADMIN: Excessive group nesting to admin
 * - PATH_COMPUTER_TAKEOVER: RBCD attack path
 * - PATH_GPO_TO_DA: GPO modification leads to DA
 *
 * MEDIUM (1):
 * - PATH_TRUST_LATERAL: Trust enables lateral movement
 */

import { ADUser, ADGroup, ADComputer, AclEntry } from '../../../../types/ad.types';
import { Finding } from '../../../../types/finding.types';
import { toAffectedUserEntities } from '../../../../utils/entity-converter';
import {
  buildGroupMembershipGraph,
  buildAclGraph,
  addDelegationEdges,
  detectNestingDepth,
  isPrivilegedMember,
  PRIVILEGED_GROUPS,
} from '../../../../utils/graph.util';
import { ADGPO } from '../../../../types/gpo.types';
import { ADTrustExtended } from '../../../../types/trust.types';

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

/**
 * Detect GPO modification paths to Domain Admin
 * Non-admins who can modify GPOs applied to privileged users/computers
 */
export function detectPathGpoToDA(
  gpos: ADGPO[],
  aclEntries: AclEntry[],
  includeDetails: boolean
): Finding {
  // Find GPOs with weak ACLs (non-admin can modify)
  const adminSids = [
    'S-1-5-32-544', // Administrators
    'S-1-5-21-*-512', // Domain Admins pattern
    'S-1-5-21-*-519', // Enterprise Admins pattern
  ];

  const vulnerableGpos: ADGPO[] = [];

  for (const gpo of gpos) {
    // Find ACLs for this GPO
    const gpoAcls = aclEntries.filter((acl) => acl.objectDn.toLowerCase() === gpo.dn.toLowerCase());

    // Check for dangerous write permissions from non-admin principals
    const hasWeakAcl = gpoAcls.some((acl) => {
      const isAdmin = adminSids.some((pattern) => {
        if (pattern.includes('*')) {
          const regex = new RegExp(pattern.replace('*', '.*'));
          return regex.test(acl.trustee);
        }
        return acl.trustee === pattern;
      });

      // Has write permission but not an admin
      const hasWrite = (acl.accessMask & 0x40000000) !== 0 || (acl.accessMask & 0x10000000) !== 0;
      // aceType is string '0' for ACCESS_ALLOWED_ACE_TYPE
      return hasWrite && !isAdmin && String(acl.aceType) === '0';
    });

    if (hasWeakAcl) {
      vulnerableGpos.push(gpo);
    }
  }

  return {
    type: 'PATH_GPO_TO_DA',
    severity: 'critical',
    category: 'attack-paths',
    title: 'GPO Modification Path to Domain Admin',
    description:
      'GPOs can be modified by non-admin users. If these GPOs apply to privileged users or DCs, attackers can achieve Domain Admin.',
    count: vulnerableGpos.length,
    affectedEntities: includeDetails ? vulnerableGpos.map((g) => g.dn) : undefined,
    details:
      vulnerableGpos.length > 0
        ? {
            vulnerableGpos: vulnerableGpos.map((g) => g.displayName || g.cn),
            attackVector: 'Modify GPO → Add malicious script/scheduled task → Execute on DA logon',
            mitigation: 'Restrict GPO modification rights, implement GPO change monitoring',
          }
        : undefined,
  };
}

/**
 * Detect ADCS certificate template paths to Domain Admin
 * Vulnerable ESC templates that enable DA compromise
 */
export function detectPathCertificateEsc(
  templates: any[],
  users: ADUser[],
  _groups: ADGroup[],
  _computers: ADComputer[],
  includeDetails: boolean
): Finding {
  // Note: groups and computers could be used for more complex enrollment permission checks

  // Find ESC1-like templates (client auth + enrollee supplies subject)
  const vulnerableTemplates = templates.filter((t) => {
    const hasClientAuth = t.pKIExtendedKeyUsage?.includes('1.3.6.1.5.5.7.3.2');
    const enrolleeSupplies = t['msPKI-Certificate-Name-Flag'] && (t['msPKI-Certificate-Name-Flag'] & 0x1) !== 0;
    return hasClientAuth && enrolleeSupplies;
  });

  if (vulnerableTemplates.length === 0) {
    return {
      type: 'PATH_CERTIFICATE_ESC',
      severity: 'critical',
      category: 'attack-paths',
      title: 'Certificate Template Escalation to Domain Admin',
      description: 'No vulnerable certificate templates that enable privilege escalation to Domain Admin.',
      count: 0,
    };
  }

  // Find non-admin users who can enroll
  // This is simplified - full check would require CA enrollment permissions
  const usersWhoCanEnroll = users.filter((u) => u.enabled && u.adminCount !== 1);

  return {
    type: 'PATH_CERTIFICATE_ESC',
    severity: 'critical',
    category: 'attack-paths',
    title: 'Certificate Template Escalation to Domain Admin',
    description:
      'Vulnerable certificate templates (ESC1-like) allow users to request certificates for any user including Domain Admins.',
    count: vulnerableTemplates.length,
    affectedEntities: includeDetails ? vulnerableTemplates.map((t) => t.dn || t.cn) : undefined,
    details: {
      vulnerableTemplates: vulnerableTemplates.map((t) => t.cn || t.name),
      attackVector: 'Enroll in vulnerable template → Request cert as DA → Authenticate as DA',
      potentialAttackers: usersWhoCanEnroll.length,
      mitigation:
        'Disable ENROLLEE_SUPPLIES_SUBJECT flag, restrict enrollment permissions, use Certificate Manager Approval',
    },
  };
}

/**
 * Detect trust relationships enabling lateral movement
 * Trusts without SID filtering or with bidirectional access
 */
export function detectPathTrustLateral(trusts: ADTrustExtended[], includeDetails: boolean): Finding {
  const riskyTrusts = trusts.filter((t) => {
    // SID filtering disabled = can inject SIDs from trusted domain
    const noSidFiltering = !t.sidFilteringEnabled;
    // Bidirectional = both domains can authenticate to each other
    const bidirectional = t.trustDirection === 3 || t.direction === 'bidirectional';
    // Forest trust without selective auth
    const forestNoSelectiveAuth = t.type === 'forest' && !t.selectiveAuthEnabled;

    return noSidFiltering || (bidirectional && forestNoSelectiveAuth);
  });

  return {
    type: 'PATH_TRUST_LATERAL',
    severity: 'high',
    category: 'attack-paths',
    title: 'Trust Relationship Enables Lateral Movement',
    description:
      'Domain trusts configured without proper security controls (SID filtering, selective authentication). Compromising trusted domain can lead to this domain.',
    count: riskyTrusts.length,
    affectedEntities: includeDetails ? riskyTrusts.map((t) => t.name) : undefined,
    details:
      riskyTrusts.length > 0
        ? {
            totalTrusts: trusts.length,
            riskyTrusts: riskyTrusts.map((t) => ({
              name: t.name,
              direction: t.direction,
              type: t.type,
              sidFiltering: t.sidFilteringEnabled,
              selectiveAuth: t.selectiveAuthEnabled,
            })),
            attackVector: 'Compromise trusted domain → Exploit trust → Access this domain',
            mitigation: 'Enable SID filtering, use selective authentication for forest trusts',
          }
        : undefined,
  };
}

/**
 * Detect all attack path vulnerabilities
 */
export function detectAttackPathVulnerabilities(
  users: ADUser[],
  groups: ADGroup[],
  computers: ADComputer[],
  aclEntries: AclEntry[],
  gpos: ADGPO[],
  trusts: ADTrustExtended[],
  templates: any[],
  includeDetails: boolean
): Finding[] {
  return [
    // Critical
    detectPathKerberoastingToDA(users, groups, computers, includeDetails),
    detectPathAclToDA(users, groups, computers, aclEntries, includeDetails),
    detectPathServiceToDA(users, groups, computers, aclEntries, includeDetails),
    detectPathCertificateEsc(templates, users, groups, computers, includeDetails),
    // High
    detectPathAsrepToAdmin(users, groups, computers, includeDetails),
    detectPathDelegationChain(users, computers, groups, includeDetails),
    detectPathNestedAdmin(users, groups, includeDetails),
    detectPathComputerTakeover(computers, users, groups, includeDetails),
    detectPathGpoToDA(gpos, aclEntries, includeDetails),
    // Medium
    detectPathTrustLateral(trusts, includeDetails),
  ].filter((finding) => finding.count > 0);
}
