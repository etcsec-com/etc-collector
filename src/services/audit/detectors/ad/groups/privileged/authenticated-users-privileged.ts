/**
 * GROUP_AUTHENTICATED_USERS_PRIVILEGED - Authenticated Users in privileged groups
 */

import { ADGroup } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';
import { toAffectedADGroupEntities } from '../../../../../../utils/entity-converter';

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
