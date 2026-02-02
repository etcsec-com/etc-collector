/**
 * GROUP_EVERYONE_IN_PRIVILEGED - Everyone group in privileged groups
 */

import { ADGroup } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';
import { toAffectedADGroupEntities } from '../../../../../../utils/entity-converter';

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
