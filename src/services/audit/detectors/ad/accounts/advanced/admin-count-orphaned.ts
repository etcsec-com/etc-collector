/**
 * Admin Count Orphaned Detector
 * Detect orphaned adminCount flag
 * Users with adminCount=1 but not actually in any admin group
 */

import { ADUser } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';
import { toAffectedUserEntities } from '../../../../../../utils/entity-converter';

export function detectAdminCountOrphaned(users: ADUser[], includeDetails: boolean): Finding {
  const adminGroups = [
    'Domain Admins',
    'Enterprise Admins',
    'Schema Admins',
    'Administrators',
    'Account Operators',
    'Server Operators',
    'Backup Operators',
    'Print Operators',
  ];

  const affected = users.filter((u) => {
    // Must have adminCount=1
    if (u.adminCount !== 1) return false;

    // Check if actually in an admin group
    const memberOf = u['memberOf'] as string[] | undefined;
    if (!memberOf || memberOf.length === 0) return true; // adminCount but no group membership

    const isInAdminGroup = memberOf.some((dn) =>
      adminGroups.some((group) => dn.toLowerCase().includes(`cn=${group.toLowerCase()}`))
    );

    return !isInAdminGroup; // adminCount=1 but not in admin group
  });

  return {
    type: 'ADMIN_COUNT_ORPHANED',
    severity: 'medium',
    category: 'accounts',
    title: 'Orphaned AdminCount Flag',
    description:
      'Accounts with adminCount=1 but not in any privileged group. This may indicate removed admins that still have residual privileges or SDProp protection.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected) : undefined,
    details:
      affected.length > 0
        ? {
            recommendation:
              'Review these accounts. If no longer admins, clear adminCount flag and reset ACLs to allow proper inheritance.',
            impact: 'Accounts may still have protected ACLs preventing proper management.',
          }
        : undefined,
  };
}
