/**
 * Delegation Privilege Detector
 * Check for delegation privilege
 */

import { ADUser } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';
import { toAffectedUserEntities } from '../../../../../../utils/entity-converter';

export function detectDelegationPrivilege(users: ADUser[], includeDetails: boolean): Finding {
  const affected = users.filter((u) => {
    return (u as any).hasSeEnableDelegationPrivilege;
  });

  return {
    type: 'DELEGATION_PRIVILEGE',
    severity: 'medium',
    category: 'advanced',
    title: 'Delegation Privilege',
    description: 'Account has SeEnableDelegationPrivilege. Can enable delegation on user/computer accounts.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected) : undefined,
  };
}
