/**
 * Account Operators Membership Detector
 * Check for Account Operators membership
 */

import { ADUser } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';
import { toAffectedUserEntities } from '../../../../../../utils/entity-converter';

export function detectAccountOperatorsMember(users: ADUser[], includeDetails: boolean): Finding {
  const affected = users.filter((u) => {
    if (!u.memberOf) return false;
    return u.memberOf.some((dn) => dn.includes('CN=Account Operators'));
  });

  return {
    type: 'ACCOUNT_OPERATORS_MEMBER',
    severity: 'high',
    category: 'accounts',
    title: 'Account Operators Member',
    description: 'Users in Account Operators group. Can create/modify user accounts.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected) : undefined,
  };
}
