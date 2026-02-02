/**
 * GROUP_EMPTY_PRIVILEGED - Empty privileged groups
 */

import { ADGroup } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';
import { toAffectedADGroupEntities } from '../../../../../../utils/entity-converter';

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
