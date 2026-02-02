/**
 * Print Operators Membership Detector
 * Check for Print Operators membership
 */

import { ADUser } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';
import { toAffectedUserEntities } from '../../../../../../utils/entity-converter';

export function detectPrintOperatorsMember(users: ADUser[], includeDetails: boolean): Finding {
  const affected = users.filter((u) => {
    if (!u.memberOf) return false;
    return u.memberOf.some((dn) => dn.includes('CN=Print Operators'));
  });

  return {
    type: 'PRINT_OPERATORS_MEMBER',
    severity: 'high',
    category: 'accounts',
    title: 'Print Operators Member',
    description: 'Users in Print Operators group. Can load drivers and manage printers on DCs.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected) : undefined,
  };
}
