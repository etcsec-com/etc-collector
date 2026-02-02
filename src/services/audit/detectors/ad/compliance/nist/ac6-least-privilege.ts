/**
 * NIST AC-6 - Least Privilege
 * Checks least privilege compliance:
 * - Users with unnecessary admin rights
 * - Excessive group memberships
 * - Accounts with elevated privileges
 */

import { ADUser, ADGroup } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';
import { toAffectedUserEntities } from '../../../../../../utils/entity-converter';

export function detectNistAc6LeastPrivilege(
  users: ADUser[],
  groups: ADGroup[],
  includeDetails: boolean
): Finding {
  const issues: { issue: string; count: number }[] = [];
  const affectedUsers: ADUser[] = [];

  const sensitiveGroups = [
    'Domain Admins',
    'Enterprise Admins',
    'Schema Admins',
    'Administrators',
    'Account Operators',
    'Backup Operators',
    'Server Operators',
    'Print Operators',
  ];

  // Check users in multiple sensitive groups
  const usersInMultipleSensitiveGroups = users.filter((u) => {
    if (!u.memberOf) return false;
    const sensitiveCount = u.memberOf.filter((dn) =>
      sensitiveGroups.some((sg) => dn.includes(`CN=${sg}`))
    ).length;
    return sensitiveCount > 1;
  });

  if (usersInMultipleSensitiveGroups.length > 0) {
    issues.push({
      issue: 'Users in multiple sensitive groups',
      count: usersInMultipleSensitiveGroups.length,
    });
    affectedUsers.push(...usersInMultipleSensitiveGroups);
  }

  // Check for excessive Domain Admins (>5)
  const domainAdmins = users.filter(
    (u) => u.memberOf?.some((dn) => dn.includes('CN=Domain Admins'))
  );
  if (domainAdmins.length > 5) {
    issues.push({
      issue: `Excessive Domain Admins (${domainAdmins.length}, recommend ≤5)`,
      count: domainAdmins.length,
    });
  }

  // Check for groups with excessive members (privilege creep indicator)
  const oversizedPrivilegedGroups = groups.filter((g) => {
    const isSensitive = sensitiveGroups.some(
      (sg) => g.sAMAccountName?.toLowerCase() === sg.toLowerCase()
    );
    return isSensitive && (g.member?.length || 0) > 10;
  });

  if (oversizedPrivilegedGroups.length > 0) {
    issues.push({
      issue: 'Privileged groups with >10 members',
      count: oversizedPrivilegedGroups.length,
    });
  }

  return {
    type: 'NIST_AC_6_LEAST_PRIVILEGE',
    severity: 'high',
    category: 'compliance',
    title: 'NIST AC-6 - Least Privilege Violations',
    description:
      'Privilege assignments do not comply with NIST AC-6 least privilege principle. Review and reduce excessive privileges.',
    count: affectedUsers.length + oversizedPrivilegedGroups.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affectedUsers.slice(0, 50)) : undefined,
    details: issues.length > 0 ? { violations: issues, framework: 'NIST', control: 'AC-6' } : undefined,
  };
}
