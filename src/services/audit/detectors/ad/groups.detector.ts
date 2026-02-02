/**
 * Groups Security Vulnerability Detector
 *
 * Detects group-related vulnerabilities in AD.
 * Story 1.7: AD Vulnerability Detection Engine
 *
 * Vulnerabilities detected (14):
 * - GPO_MODIFY_RIGHTS (High)
 * - DNS_ADMINS_MEMBER (High)
 * - OVERSIZED_GROUP_CRITICAL (High)
 * - OVERSIZED_GROUP_HIGH (Medium)
 * - OVERSIZED_GROUP (Medium)
 * - PRE_WINDOWS_2000_ACCESS (Medium)
 * - DANGEROUS_GROUP_NESTING (Medium)
 * - GROUP_EMPTY_PRIVILEGED (Low) - Phase 2C
 * - GROUP_CIRCULAR_NESTING (Medium) - Phase 2C
 * - GROUP_EXCESSIVE_MEMBERS (Medium) - Phase 2C
 * - BUILTIN_MODIFIED (High) - Phase 2C
 * - GROUP_EVERYONE_IN_PRIVILEGED (Critical) - Phase 4
 * - GROUP_AUTHENTICATED_USERS_PRIVILEGED (High) - Phase 4
 * - GROUP_PROTECTED_USERS_EMPTY (Medium) - Phase 4
 */

import { ADUser, ADGroup } from '../../../../types/ad.types';
import { Finding } from '../../../../types/finding.types';
import { toAffectedUserEntities, toAffectedADGroupEntities } from '../../../../utils/entity-converter';

/**
 * Check for Group Policy Creator Owners membership
 */
export function detectGpoModifyRights(users: ADUser[], includeDetails: boolean): Finding {
  const affected = users.filter((u) => {
    if (!u.memberOf) return false;
    return u.memberOf.some((dn) => dn.includes('CN=Group Policy Creator Owners'));
  });

  return {
    type: 'GPO_MODIFY_RIGHTS',
    severity: 'high',
    category: 'groups',
    title: 'Group Policy Creator Owners Member',
    description: 'Users in Group Policy Creator Owners group. Can create/modify GPOs and execute code on domain machines.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected) : undefined,
  };
}

/**
 * Check for DnsAdmins membership
 */
export function detectDnsAdminsMember(users: ADUser[], includeDetails: boolean): Finding {
  const affected = users.filter((u) => {
    if (!u.memberOf) return false;
    return u.memberOf.some((dn) => dn.includes('CN=DnsAdmins'));
  });

  return {
    type: 'DNS_ADMINS_MEMBER',
    severity: 'high',
    category: 'groups',
    title: 'DnsAdmins Member',
    description: 'Users in DnsAdmins group. Can load arbitrary DLLs on domain controllers (escalation to Domain Admin).',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected) : undefined,
  };
}

/**
 * Check for Pre-Windows 2000 Compatible Access membership
 */
export function detectPreWindows2000Access(users: ADUser[], includeDetails: boolean): Finding {
  const affected = users.filter((u) => {
    if (!u.memberOf) return false;
    return u.memberOf.some((dn) => dn.includes('CN=Pre-Windows 2000 Compatible Access'));
  });

  return {
    type: 'PRE_WINDOWS_2000_ACCESS',
    severity: 'medium',
    category: 'groups',
    title: 'Pre-Windows 2000 Compatible Access',
    description: 'Pre-Windows 2000 Compatible Access group has members. Overly permissive read access to AD objects.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected) : undefined,
  };
}

/**
 * Check for oversized groups (500+ members)
 * PingCastle threshold: >500 members = critical
 */
export function detectOversizedGroupCritical(groups: ADGroup[], includeDetails: boolean): Finding {
  const affected = groups.filter((g) => {
    if (!g.member) return false;
    return g.member.length > 500;
  });

  return {
    type: 'OVERSIZED_GROUP_CRITICAL',
    severity: 'high',
    category: 'groups',
    title: 'Oversized Group (Critical)',
    description: 'Groups with 500+ members. Management/audit difficulty, excessive privileges, performance issues.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedADGroupEntities(affected) : undefined,
  };
}

/**
 * Check for oversized groups (200-500 members)
 */
export function detectOversizedGroupHigh(groups: ADGroup[], includeDetails: boolean): Finding {
  const affected = groups.filter((g) => {
    if (!g.member) return false;
    return g.member.length > 200 && g.member.length <= 500;
  });

  return {
    type: 'OVERSIZED_GROUP_HIGH',
    severity: 'medium',
    category: 'groups',
    title: 'Oversized Group (High)',
    description: 'Groups with 200-500 members. Management difficulty and potential privilege creep.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedADGroupEntities(affected) : undefined,
  };
}

/**
 * Check for oversized groups (100-500 members)
 */
export function detectOversizedGroup(groups: ADGroup[], includeDetails: boolean): Finding {
  const affected = groups.filter((g) => {
    if (!g.member) return false;
    return g.member.length > 100 && g.member.length <= 500;
  });

  return {
    type: 'OVERSIZED_GROUP',
    severity: 'medium',
    category: 'groups',
    title: 'Oversized Group',
    description: 'Groups with 100-500 members. May indicate overly broad permissions.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedADGroupEntities(affected) : undefined,
  };
}

/**
 * Check for dangerous group nesting (sensitive groups nested in less sensitive groups)
 */
export function detectDangerousGroupNesting(groups: ADGroup[], includeDetails: boolean): Finding {
  const protectedGroups = [
    'Domain Admins',
    'Enterprise Admins',
    'Schema Admins',
    'Administrators',
    'Account Operators',
    'Backup Operators',
    'Server Operators',
    'Print Operators',
  ];

  const affected = groups.filter((g) => {
    if (!g.memberOf) return false;

    // Check if this is a protected group
    const isProtected = protectedGroups.some((pg) => g.dn.includes(`CN=${pg}`));
    if (!isProtected) return false;

    // Check if it's nested in a non-protected group
    const hasUnexpectedNesting = g.memberOf.some((dn) => {
      return !protectedGroups.some((pg) => dn.includes(`CN=${pg}`));
    });

    return hasUnexpectedNesting;
  });

  return {
    type: 'DANGEROUS_GROUP_NESTING',
    severity: 'medium',
    category: 'groups',
    title: 'Dangerous Group Nesting',
    description: 'Sensitive group nested in less sensitive group. Unintended privilege escalation path.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedADGroupEntities(affected) : undefined,
  };
}

// ==================== PHASE 2C DETECTORS ====================

/**
 * Detect empty privileged groups
 * Privileged groups should either be used or documented as intentionally empty
 */
export function detectGroupEmptyPrivileged(groups: ADGroup[], includeDetails: boolean): Finding {
  const privilegedGroups = [
    'Domain Admins',
    'Enterprise Admins',
    'Schema Admins',
    'Administrators',
    'Account Operators',
    'Server Operators',
    'Backup Operators',
    'Print Operators',
    'DnsAdmins',
    'Group Policy Creator Owners',
  ];

  const affected = groups.filter((g) => {
    const name = g.sAMAccountName || g.displayName || '';
    const isPrivileged = privilegedGroups.some(
      (pg) => name.toLowerCase() === pg.toLowerCase() || g.dn.toLowerCase().includes(`cn=${pg.toLowerCase()}`)
    );

    if (!isPrivileged) return false;

    // Check if group is empty
    const memberCount = g.member?.length ?? 0;
    return memberCount === 0;
  });

  return {
    type: 'GROUP_EMPTY_PRIVILEGED',
    severity: 'low',
    category: 'groups',
    title: 'Empty Privileged Group',
    description:
      'Privileged groups with no members. While not a vulnerability, empty admin groups may indicate misconfiguration or unused infrastructure.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedADGroupEntities(affected) : undefined,
    details:
      affected.length > 0
        ? {
            groups: affected.map((g) => g.sAMAccountName || g.dn),
            recommendation: 'Document intentionally empty groups or remove if unused.',
          }
        : undefined,
  };
}

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

/**
 * Detect builtin groups with non-standard members
 * Builtin groups should only contain expected system accounts
 */
export function detectBuiltinModified(groups: ADGroup[], includeDetails: boolean): Finding {
  // Builtin groups and their expected default members
  const builtinDefaults: { [key: string]: string[] } = {
    Administrators: ['Administrator', 'Domain Admins', 'Enterprise Admins'],
    Users: ['Domain Users', 'Authenticated Users', 'INTERACTIVE'],
    Guests: ['Guest', 'Domain Guests'],
    'Remote Desktop Users': [],
    'Network Configuration Operators': [],
    'Performance Monitor Users': [],
    'Performance Log Users': [],
    'Distributed COM Users': [],
    'IIS_IUSRS': [],
    'Cryptographic Operators': [],
    'Event Log Readers': [],
    'Certificate Service DCOM Access': [],
  };

  const affected = groups.filter((g) => {
    const name = g.sAMAccountName || '';

    // Check if it's a builtin group we monitor
    if (!builtinDefaults[name]) return false;

    const expectedMembers = builtinDefaults[name];
    const actualMembers = g.member ?? [];

    // Check for unexpected members
    const hasUnexpectedMembers = actualMembers.some((memberDn) => {
      const memberCn = memberDn.match(/CN=([^,]+)/i)?.[1] || '';
      // Check if this member is in the expected list
      return !expectedMembers.some((exp) => memberCn.toLowerCase().includes(exp.toLowerCase()));
    });

    return hasUnexpectedMembers;
  });

  return {
    type: 'BUILTIN_MODIFIED',
    severity: 'high',
    category: 'groups',
    title: 'Builtin Group Modified',
    description:
      'Builtin groups contain non-standard members. This may indicate privilege escalation or backdoor access.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedADGroupEntities(affected) : undefined,
    details:
      affected.length > 0
        ? {
            groups: affected.map((g) => g.sAMAccountName || g.dn),
            recommendation:
              'Review membership of builtin groups and remove unexpected members. Document any intentional additions.',
            risk: 'Attackers often add accounts to builtin groups for persistent access.',
          }
        : undefined,
  };
}

/**
 * Detect Everyone group in privileged groups
 *
 * The Everyone principal should never be a member of privileged groups.
 * This grants all users (including anonymous) privileged access.
 *
 * @param groups - Array of AD groups
 * @param includeDetails - Whether to include affected entity details
 * @returns Finding for GROUP_EVERYONE_IN_PRIVILEGED
 */
export function detectGroupEveryoneInPrivileged(
  groups: ADGroup[],
  includeDetails: boolean
): Finding {
  const privilegedGroups = [
    'Domain Admins',
    'Enterprise Admins',
    'Schema Admins',
    'Administrators',
    'Account Operators',
    'Server Operators',
    'Backup Operators',
    'Print Operators',
  ];

  const affected = groups.filter((g) => {
    const groupName = g.sAMAccountName || g.cn || '';
    const isPrivileged = privilegedGroups.some(
      (pg) => groupName.toLowerCase() === pg.toLowerCase()
    );
    if (!isPrivileged || !g.member) return false;

    // Check if Everyone (S-1-1-0) or World is a member
    return g.member.some(
      (m) =>
        m.toLowerCase().includes('everyone') ||
        m.includes('S-1-1-0') ||
        m.toLowerCase().includes('world')
    );
  });

  return {
    type: 'GROUP_EVERYONE_IN_PRIVILEGED',
    severity: 'critical',
    category: 'groups',
    title: 'Everyone in Privileged Group',
    description:
      'The Everyone principal is a member of a privileged group. ' +
      'This grants ALL users (including anonymous) administrative privileges.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedADGroupEntities(affected) : undefined,
    details: {
      recommendation: 'Immediately remove Everyone from privileged groups.',
      risk: 'Complete domain compromise - anyone can authenticate as admin.',
    },
  };
}

/**
 * Detect Authenticated Users in privileged groups
 *
 * Authenticated Users should not be members of privileged groups.
 * This grants all domain users admin access.
 *
 * @param groups - Array of AD groups
 * @param includeDetails - Whether to include affected entity details
 * @returns Finding for GROUP_AUTHENTICATED_USERS_PRIVILEGED
 */
export function detectGroupAuthenticatedUsersPrivileged(
  groups: ADGroup[],
  includeDetails: boolean
): Finding {
  const privilegedGroups = [
    'Domain Admins',
    'Enterprise Admins',
    'Schema Admins',
    'Administrators',
    'Account Operators',
    'Server Operators',
    'Backup Operators',
  ];

  const affected = groups.filter((g) => {
    const groupName = g.sAMAccountName || g.cn || '';
    const isPrivileged = privilegedGroups.some(
      (pg) => groupName.toLowerCase() === pg.toLowerCase()
    );
    if (!isPrivileged || !g.member) return false;

    // Check if Authenticated Users (S-1-5-11) is a member
    return g.member.some(
      (m) =>
        m.toLowerCase().includes('authenticated users') ||
        m.includes('S-1-5-11') ||
        m.toLowerCase().includes('utilisateurs authentifiés')
    );
  });

  return {
    type: 'GROUP_AUTHENTICATED_USERS_PRIVILEGED',
    severity: 'high',
    category: 'groups',
    title: 'Authenticated Users in Privileged Group',
    description:
      'Authenticated Users principal is a member of a privileged group. ' +
      'This grants ALL authenticated domain users administrative privileges.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedADGroupEntities(affected) : undefined,
    details: {
      recommendation: 'Remove Authenticated Users from privileged groups immediately.',
      risk: 'Any domain user can perform administrative actions.',
    },
  };
}

/**
 * Detect empty Protected Users group
 *
 * The Protected Users group provides enhanced security for privileged accounts.
 * If empty, privileged accounts lack these protections.
 *
 * @param groups - Array of AD groups
 * @param _includeDetails - Whether to include affected entity details
 * @returns Finding for GROUP_PROTECTED_USERS_EMPTY
 */
export function detectGroupProtectedUsersEmpty(
  groups: ADGroup[],
  _includeDetails: boolean
): Finding {
  const protectedUsersGroup = groups.find(
    (g) =>
      (g.sAMAccountName || g.cn || '').toLowerCase() === 'protected users'
  );

  const isEmpty =
    !protectedUsersGroup ||
    !protectedUsersGroup.member ||
    protectedUsersGroup.member.length === 0;

  return {
    type: 'GROUP_PROTECTED_USERS_EMPTY',
    severity: 'medium',
    category: 'groups',
    title: 'Protected Users Group Empty',
    description:
      'The Protected Users group has no members. ' +
      'Privileged accounts should be added to this group for enhanced security (NTLM disabled, Kerberos delegation blocked, credential caching prevented).',
    count: isEmpty ? 1 : 0,
    details: {
      memberCount: protectedUsersGroup?.member?.length || 0,
      recommendation:
        'Add Domain Admins, Enterprise Admins, and other privileged accounts to Protected Users group.',
      benefits: [
        'NTLM authentication disabled',
        'Kerberos delegation blocked',
        'Credential caching prevented',
        'DES/RC4 encryption disabled',
      ],
    },
  };
}

/**
 * Detect excessive privileged accounts
 * Flags when there are too many accounts in high-privilege groups
 * PingCastle threshold: > 10 Domain Admins, > 50 total privileged
 */
export function detectExcessivePrivilegedAccounts(
  users: ADUser[],
  groups: ADGroup[],
  includeDetails: boolean
): Finding {
  const privilegedGroupNames = [
    'Domain Admins',
    'Enterprise Admins',
    'Schema Admins',
    'Administrators',
    'Account Operators',
    'Backup Operators',
    'Server Operators',
    'Print Operators',
  ];

  // Count unique privileged users
  const privilegedUsers = new Set<string>();
  const groupCounts: Record<string, number> = {};

  for (const user of users) {
    if (!user.memberOf) continue;
    for (const groupDn of user.memberOf) {
      for (const groupName of privilegedGroupNames) {
        if (groupDn.toUpperCase().includes(`CN=${groupName.toUpperCase()}`)) {
          privilegedUsers.add(user.dn);
          groupCounts[groupName] = (groupCounts[groupName] || 0) + 1;
        }
      }
    }
  }

  // Also count from group membership directly
  for (const group of groups) {
    const groupName = privilegedGroupNames.find((name) =>
      group.sAMAccountName?.toUpperCase() === name.toUpperCase() ||
      group.dn?.toUpperCase().includes(`CN=${name.toUpperCase()}`)
    );
    if (groupName && group.member) {
      groupCounts[groupName] = Math.max(groupCounts[groupName] || 0, group.member.length);
    }
  }

  const totalPrivileged = privilegedUsers.size;
  const domainAdmins = groupCounts['Domain Admins'] || 0;
  const enterpriseAdmins = groupCounts['Enterprise Admins'] || 0;

  // Flag if > 10 Domain Admins OR > 50 total privileged (PingCastle thresholds)
  const isExcessive = domainAdmins > 10 || totalPrivileged > 50;

  return {
    type: 'EXCESSIVE_PRIVILEGED_ACCOUNTS',
    severity: isExcessive ? 'medium' : 'low',
    category: 'groups',
    title: 'Excessive Privileged Accounts',
    description:
      'Large number of accounts with administrative privileges increases attack surface. ' +
      'Each privileged account is a potential target for credential theft.',
    count: isExcessive ? totalPrivileged : 0,
    affectedEntities: includeDetails && isExcessive
      ? Array.from(privilegedUsers).map((dn) => {
          const user = users.find((u) => u.dn === dn);
          if (user) {
            const entities = toAffectedUserEntities([user]);
            return entities[0] || dn;
          }
          return dn;
        })
      : undefined,
    details: {
      totalPrivilegedUsers: totalPrivileged,
      domainAdmins,
      enterpriseAdmins,
      schemaAdmins: groupCounts['Schema Admins'] || 0,
      administrators: groupCounts['Administrators'] || 0,
      accountOperators: groupCounts['Account Operators'] || 0,
      backupOperators: groupCounts['Backup Operators'] || 0,
      serverOperators: groupCounts['Server Operators'] || 0,
      printOperators: groupCounts['Print Operators'] || 0,
      threshold: 'Domain Admins > 10 or total privileged > 50',
      recommendation: 'Review privileged group memberships and apply least privilege principle.',
    },
  };
}

/**
 * Detect all group-related vulnerabilities
 */
export function detectGroupsVulnerabilities(
  users: ADUser[],
  groups: ADGroup[],
  includeDetails: boolean
): Finding[] {
  return [
    // User membership checks
    detectGpoModifyRights(users, includeDetails),
    detectDnsAdminsMember(users, includeDetails),
    detectPreWindows2000Access(users, includeDetails),
    // Group analysis checks
    detectOversizedGroupCritical(groups, includeDetails),
    detectOversizedGroupHigh(groups, includeDetails),
    detectOversizedGroup(groups, includeDetails),
    detectDangerousGroupNesting(groups, includeDetails),
    // Phase 2C: Enhanced detections
    detectGroupEmptyPrivileged(groups, includeDetails),
    detectGroupCircularNesting(groups, includeDetails),
    detectGroupExcessiveMembers(groups, includeDetails),
    detectBuiltinModified(groups, includeDetails),
    // Phase 4: Advanced detections
    detectGroupEveryoneInPrivileged(groups, includeDetails),
    detectGroupAuthenticatedUsersPrivileged(groups, includeDetails),
    detectGroupProtectedUsersEmpty(groups, includeDetails),
    // NEW: Excessive privileged accounts
    detectExcessivePrivilegedAccounts(users, groups, includeDetails),
  ].filter((finding) => finding.count > 0);
}
