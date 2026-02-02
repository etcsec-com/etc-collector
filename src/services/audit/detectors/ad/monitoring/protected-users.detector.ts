/**
 * Protected Users Detector
 *
 * Detects if Protected Users group is not being used.
 * Protected Users provides additional protections for privileged accounts.
 */

import { ADUser, ADGroup } from '../../../../../types/ad.types';
import { Finding } from '../../../../../types/finding.types';
import { toAffectedUserEntities } from '../../../../../utils/entity-converter';

/**
 * Detect if Protected Users group is not being used
 * Protected Users provides additional protections for privileged accounts
 */
export function detectNoProtectedUsersMonitoring(
  users: ADUser[],
  groups: ADGroup[],
  includeDetails: boolean
): Finding {
  // Find the Protected Users group
  const protectedUsersGroup = groups.find((g) => {
    const name = (g.sAMAccountName || g.displayName || '').toLowerCase();
    return name === 'protected users' || g.dn.toLowerCase().includes('cn=protected users');
  });

  // Get privileged users who should be in Protected Users
  const privilegedUsers = users.filter((u) => u.adminCount === 1 && u.enabled);

  // Check which privileged users are NOT in Protected Users
  const notInProtectedUsers = privilegedUsers.filter((u) => {
    const memberOf = u['memberOf'] as string[] | undefined;
    if (!memberOf) return true;

    // Check if any membership is Protected Users
    return !memberOf.some(
      (g) =>
        g.toLowerCase().includes('cn=protected users') ||
        (protectedUsersGroup && g.toLowerCase() === protectedUsersGroup.dn.toLowerCase())
    );
  });

  // If no Protected Users group found or it's empty
  const groupExists = protectedUsersGroup !== undefined;
  const groupMemberCount = protectedUsersGroup?.member?.length ?? 0;

  return {
    type: 'NO_PROTECTED_USERS_MONITORING',
    severity: 'medium',
    category: 'monitoring',
    title: 'Protected Users Group Not Utilized',
    description:
      'Privileged accounts are not members of the Protected Users group. This group provides additional protections against credential theft.',
    count: notInProtectedUsers.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(notInProtectedUsers) : undefined,
    details: {
      groupExists,
      currentMembers: groupMemberCount,
      totalPrivilegedAccounts: privilegedUsers.length,
      notInGroup: notInProtectedUsers.length,
      protections: [
        'NTLM authentication disabled',
        'Kerberos DES/RC4 encryption disabled',
        'Kerberos TGT lifetime reduced to 4 hours',
        'Credential delegation disabled',
        'Cached credentials not stored',
      ],
      recommendation:
        'Add all privileged/admin accounts to Protected Users group for enhanced credential protection.',
    },
  };
}
