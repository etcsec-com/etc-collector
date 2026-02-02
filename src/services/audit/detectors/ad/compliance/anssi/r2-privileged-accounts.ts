/**
 * ANSSI R2 - Privileged Accounts Management
 * Checks privileged account compliance:
 * - Admin accounts should have separate user accounts
 * - Admin accounts should not have email
 * - Admin accounts should require smartcard
 * - Number of Domain Admins should be limited (<10)
 */

import { ADUser, ADGroup } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';
import { toAffectedUserEntities } from '../../../../../../utils/entity-converter';

export function detectAnssiR2PrivilegedAccounts(
  users: ADUser[],
  _groups: ADGroup[],
  includeDetails: boolean
): Finding {
  const privilegedGroups = ['Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators'];
  const issues: { user: string; violations: string[] }[] = [];

  const privilegedUsers = users.filter((u) => {
    if (!u.memberOf) return false;
    return u.memberOf.some((dn) => privilegedGroups.some((pg) => dn.includes(`CN=${pg}`)));
  });

  // Check each privileged user
  for (const user of privilegedUsers) {
    const userIssues: string[] = [];

    // Admin account with email configured (should use separate account)
    if (user.mail) {
      userIssues.push('Admin account has email configured (use separate account)');
    }

    // Admin account without smartcard required
    const uac = user.userAccountControl || 0;
    if ((uac & 0x40000) === 0) {
      // SMARTCARD_REQUIRED flag not set
      userIssues.push('Smartcard not required for privileged account');
    }

    // Admin account enabled but never logged on
    if (user.enabled && !user.lastLogon) {
      userIssues.push('Enabled admin account never logged on');
    }

    if (userIssues.length > 0) {
      issues.push({ user: user.sAMAccountName, violations: userIssues });
    }
  }

  // Check total number of Domain Admins
  const domainAdmins = privilegedUsers.filter((u) =>
    u.memberOf?.some((dn) => dn.includes('CN=Domain Admins'))
  );
  const domainAdminCount = domainAdmins.length;

  return {
    type: 'ANSSI_R2_PRIVILEGED_ACCOUNTS',
    severity: 'high',
    category: 'compliance',
    title: 'ANSSI R2 - Privileged Accounts Non-Compliant',
    description:
      'Privileged accounts do not meet ANSSI R2 recommendations. Admin accounts should use separate identities, require smartcard, and not exceed 10 Domain Admins.',
    count: issues.length,
    affectedEntities: includeDetails
      ? toAffectedUserEntities(
          users.filter((u) => issues.some((i) => i.user === u.sAMAccountName))
        )
      : undefined,
    details:
      issues.length > 0
        ? {
            violations: issues.slice(0, 10),
            domainAdminCount,
            recommendation:
              domainAdminCount > 10
                ? `Reduce Domain Admins from ${domainAdminCount} to ≤10`
                : undefined,
            framework: 'ANSSI',
            control: 'R2',
          }
        : undefined,
  };
}
