/**
 * Locked Account Admin Detector
 * Detect locked admin accounts
 *
 * Administrative accounts that are currently locked may indicate
 * ongoing attack attempts or credential compromise.
 */

import { ADUser } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';
import { toAffectedUserEntities } from '../../../../../../utils/entity-converter';

export function detectLockedAccountAdmin(users: ADUser[], includeDetails: boolean): Finding {
  const adminGroups = [
    'Domain Admins',
    'Enterprise Admins',
    'Schema Admins',
    'Administrators',
    'Account Operators',
    'Server Operators',
    'Backup Operators',
  ];

  const affected = users.filter((u) => {
    if (!u.memberOf) return false;
    // Check if account is locked (lockoutTime != 0 or UAC flag 0x10)
    const isLocked =
      (u.lockoutTime && u.lockoutTime !== '0' && u.lockoutTime !== 0) ||
      (u.userAccountControl && (u.userAccountControl & 0x10) !== 0);

    const isAdmin = u.memberOf.some((dn) =>
      adminGroups.some((g) => dn.toLowerCase().includes(g.toLowerCase()))
    );

    return isLocked && isAdmin;
  });

  return {
    type: 'LOCKED_ACCOUNT_ADMIN',
    severity: 'high',
    category: 'accounts',
    title: 'Locked Administrative Account',
    description:
      'Administrative accounts that are currently locked out. ' +
      'May indicate password spray attacks or compromised credential attempts.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected) : undefined,
    details: {
      recommendation:
        'Investigate why these admin accounts are locked. Check security logs for failed authentication attempts.',
    },
  };
}
