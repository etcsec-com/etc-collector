/**
 * GROUP_PROTECTED_USERS_EMPTY - Empty Protected Users group
 */

import { ADGroup } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';

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
