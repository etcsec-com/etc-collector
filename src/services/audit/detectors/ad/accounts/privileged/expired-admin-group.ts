/**
 * Expired Account in Admin Group Detector
 * Check for expired accounts still in admin groups
 */

import { ADUser } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';
import { toAffectedUserEntities } from '../../../../../../utils/entity-converter';

export function detectExpiredAccountInAdminGroup(users: ADUser[], includeDetails: boolean): Finding {
  const adminGroups = ['Domain Admins', 'Enterprise Admins', 'Schema Admins'];
  const now = Date.now();

  const affected = users.filter((u) => {
    if (!u.memberOf) return false;
    const accountExpires = (u as any)['accountExpires'] as Date | undefined;
    const isExpired = accountExpires && accountExpires.getTime() < now;
    const isInAdminGroup = u.memberOf.some((dn: string) =>
      adminGroups.some((group) => dn.includes(`CN=${group}`))
    );
    return isExpired && isInAdminGroup;
  });

  return {
    type: 'EXPIRED_ACCOUNT_IN_ADMIN_GROUP',
    severity: 'high',
    category: 'accounts',
    title: 'Expired Account in Admin Group',
    description: 'Expired user accounts still present in privileged groups. Should be removed immediately.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected) : undefined,
  };
}
