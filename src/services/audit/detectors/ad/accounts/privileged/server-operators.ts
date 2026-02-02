/**
 * Server Operators Membership Detector
 * Check for Server Operators membership
 */

import { ADUser } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';
import { toAffectedUserEntities } from '../../../../../../utils/entity-converter';

export function detectServerOperatorsMember(users: ADUser[], includeDetails: boolean): Finding {
  const affected = users.filter((u) => {
    if (!u.memberOf) return false;
    return u.memberOf.some((dn) => dn.includes('CN=Server Operators'));
  });

  return {
    type: 'SERVER_OPERATORS_MEMBER',
    severity: 'high',
    category: 'accounts',
    title: 'Server Operators Member',
    description: 'Users in Server Operators group. Can manage domain controllers.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected) : undefined,
  };
}
