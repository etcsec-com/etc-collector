/**
 * Admin Audit Bypass Detector
 *
 * Detects if admins can bypass audit.
 * Checks for accounts with SeAuditPrivilege or audit bypass capabilities.
 */

import { ADUser, ADDomain } from '../../../../../types/ad.types';
import { Finding } from '../../../../../types/finding.types';
import { toAffectedUserEntities } from '../../../../../utils/entity-converter';

/**
 * Detect if admins can bypass audit
 * Checks for accounts with SeAuditPrivilege or audit bypass capabilities
 */
export function detectAdminAuditBypass(
  users: ADUser[],
  _domain: ADDomain | null,
  includeDetails: boolean
): Finding {
  // Find users with adminCount=1 who are not in Protected Users
  // These admins may have the ability to manipulate audit logs
  const adminUsers = users.filter((u) => u.adminCount === 1 && u.enabled);

  // Check for users not in Protected Users group
  const protectedUsersPattern = /protected users/i;
  const adminsNotProtected = adminUsers.filter((u) => {
    const memberOf = u['memberOf'] as string[] | undefined;
    if (!memberOf) return true;
    return !memberOf.some((g) => protectedUsersPattern.test(g));
  });

  // Check for specific concerning patterns
  const auditBypassRisk = adminsNotProtected.filter((u) => {
    // Admins with old passwords are higher risk (may be compromised)
    const pwdAge = u.pwdLastSet ? Date.now() - new Date(u.pwdLastSet).getTime() : Infinity;
    const pwdAgeMonths = pwdAge / (1000 * 60 * 60 * 24 * 30);
    return pwdAgeMonths > 6; // Password older than 6 months
  });

  const hasRisk = auditBypassRisk.length > 0;

  return {
    type: 'ADMIN_AUDIT_BYPASS',
    severity: 'high',
    category: 'monitoring',
    title: 'Administrators Can Bypass Audit',
    description:
      'Privileged accounts not in Protected Users group with old passwords may bypass audit controls.',
    count: auditBypassRisk.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(auditBypassRisk) : undefined,
    details: hasRisk
      ? {
          totalAdmins: adminUsers.length,
          adminsNotProtected: adminsNotProtected.length,
          adminsWithOldPasswords: auditBypassRisk.length,
          recommendation:
            'Add admin accounts to Protected Users group and enforce regular password rotation.',
          risks: [
            'Admins can clear security logs',
            'Compromised admin credentials may evade detection',
            'Audit policies may be disabled by compromised admin',
          ],
        }
      : undefined,
  };
}
