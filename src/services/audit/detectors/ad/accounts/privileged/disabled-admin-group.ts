/**
 * Disabled Account in Admin Group Detector
 * Check for disabled accounts still in admin groups
 */

import { ADUser } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';
import { toAffectedUserEntities } from '../../../../../../utils/entity-converter';

export function detectDisabledAccountInAdminGroup(users: ADUser[], includeDetails: boolean): Finding {
  const adminGroups = ['Domain Admins', 'Enterprise Admins', 'Schema Admins'];

  const affected = users.filter((u) => {
    if (!u.userAccountControl || !u.memberOf) return false;
    const isDisabled = (u.userAccountControl & 0x2) !== 0;
    const isInAdminGroup = u.memberOf.some((dn) =>
      adminGroups.some((group) => dn.includes(`CN=${group}`))
    );
    return isDisabled && isInAdminGroup;
  });

  return {
    type: 'DISABLED_ACCOUNT_IN_ADMIN_GROUP',
    severity: 'high',
    category: 'accounts',
    title: 'Disabled Account in Admin Group',
    description: 'Disabled user accounts still present in privileged groups. Should be removed immediately.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected) : undefined,
  };
}
