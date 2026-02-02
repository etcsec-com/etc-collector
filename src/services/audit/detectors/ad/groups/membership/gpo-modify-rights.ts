/**
 * GPO_MODIFY_RIGHTS - Group Policy Creator Owners membership
 */

import { ADUser } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';
import { toAffectedUserEntities } from '../../../../../../utils/entity-converter';

/**
 * Check for Group Policy Creator Owners membership
 */
export function detectGpoModifyRights(users: ADUser[], includeDetails: boolean): Finding {
  const affected = users.filter((u) => {
    if (!u.memberOf) return false;
    return u.memberOf.some((dn) => dn.includes('CN=Group Policy Creator Owners'));
  });

  return {
    type: 'GPO_MODIFY_RIGHTS',
    severity: 'high',
    category: 'groups',
    title: 'Group Policy Creator Owners Member',
    description: 'Users in Group Policy Creator Owners group. Can create/modify GPOs and execute code on domain machines.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected) : undefined,
  };
}
