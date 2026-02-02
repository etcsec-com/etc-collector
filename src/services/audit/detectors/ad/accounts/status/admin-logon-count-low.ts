/**
 * Admin Logon Count Low Detector
 * Check for admin accounts with very low logon count
 * May indicate unused admin accounts or recently created accounts with elevated privileges
 */

import { ADUser } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';
import { toAffectedUserEntities } from '../../../../../../utils/entity-converter';

export function detectAdminLogonCountLow(users: ADUser[], includeDetails: boolean): Finding {
  const affected = users.filter((u) => {
    // Must be enabled
    if (!u.enabled) return false;
    // Must be marked as admin (adminCount = 1)
    if (u.adminCount !== 1) return false;
    // Check logon count (accessible via index signature)
    const logonCount = (u as any)['logonCount'] as number | undefined;
    // Low logon count (less than 5)
    return logonCount !== undefined && logonCount < 5;
  });

  return {
    type: 'ADMIN_LOGON_COUNT_LOW',
    severity: 'low',
    category: 'accounts',
    title: 'Admin Account with Low Logon Count',
    description:
      'Administrative accounts (adminCount=1) with fewer than 5 logons. May indicate unused privileged accounts that should be reviewed or disabled.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected) : undefined,
  };
}
