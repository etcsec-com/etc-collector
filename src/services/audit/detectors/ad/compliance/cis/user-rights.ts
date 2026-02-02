/**
 * CIS User Rights (2.3.11.x)
 * Checks CIS Benchmark user rights assignments
 */

import { ADUser, ADGroup } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';

export function detectCisUserRights(
  users: ADUser[],
  groups: ADGroup[],
  _includeDetails: boolean
): Finding {
  const issues: string[] = [];

  // Check for Everyone or Authenticated Users in privileged groups
  const sensitiveGroups = ['Administrators', 'Domain Admins', 'Enterprise Admins'];
  const problematicMembers = ['Everyone', 'Authenticated Users', 'ANONYMOUS LOGON'];

  for (const group of groups) {
    const isSensitive = sensitiveGroups.some(
      (sg) => group.sAMAccountName?.toLowerCase() === sg.toLowerCase()
    );
    if (!isSensitive) continue;

    const hasProblematicMember = group.member?.some((memberDn) =>
      problematicMembers.some((pm) => memberDn.toLowerCase().includes(pm.toLowerCase()))
    );

    if (hasProblematicMember) {
      issues.push(`${group.sAMAccountName} contains well-known security principal (CIS 2.3.11.x)`);
    }
  }

  // Check for accounts with "Act as part of the operating system" potential
  const trustedForDelegation = users.filter((u) => {
    const uac = u.userAccountControl || 0;
    return (uac & 0x80000) !== 0; // TRUSTED_FOR_DELEGATION
  });

  if (trustedForDelegation.length > 0) {
    issues.push(`${trustedForDelegation.length} users trusted for delegation (CIS 2.3.11.x)`);
  }

  return {
    type: 'CIS_USER_RIGHTS',
    severity: 'medium',
    category: 'compliance',
    title: 'CIS Benchmark - User Rights Issues',
    description:
      'User rights assignments do not meet CIS Benchmark recommendations. Review delegation and group memberships.',
    count: issues.length > 0 ? 1 : 0,
    details: issues.length > 0 ? { violations: issues, framework: 'CIS', control: '2.3.11.x' } : undefined,
  };
}
