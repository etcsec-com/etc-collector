/**
 * EXCESSIVE_PRIVILEGED_ACCOUNTS - Too many accounts in high-privilege groups
 */

import { ADUser, ADGroup } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';
import { toAffectedUserEntities } from '../../../../../../utils/entity-converter';

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
