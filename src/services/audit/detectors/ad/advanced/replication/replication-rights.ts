/**
 * Replication Rights Detector
 * Check for accounts with replication rights (potential DCSync)
 */

import { ADUser } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';
import { toAffectedUserEntities } from '../../../../../../utils/entity-converter';

export function detectReplicationRights(users: ADUser[], includeDetails: boolean): Finding {
  const affected = users.filter((u) => {
    // adminCount=1 but not in standard admin groups
    if (u.adminCount !== 1) return false;
    if (!u.memberOf) return true; // Has adminCount but no groups

    const isInStandardAdminGroups = u.memberOf.some((dn) => {
      return (
        dn.includes('CN=Domain Admins') ||
        dn.includes('CN=Enterprise Admins') ||
        dn.includes('CN=Administrators')
      );
    });

    return !isInStandardAdminGroups;
  });

  return {
    type: 'REPLICATION_RIGHTS',
    severity: 'high',
    category: 'advanced',
    title: 'Replication Rights',
    description: 'Account with adminCount=1 outside standard admin groups. May have replication rights (DCSync).',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected) : undefined,
  };
}
