/**
 * Unconstrained Delegation Detector
 *
 * Detects user accounts with unconstrained Kerberos delegation enabled.
 * UAC flag 0x80000 = TRUSTED_FOR_DELEGATION
 */

import { ADUser } from '../../../../../types/ad.types';
import { Finding } from '../../../../../types/finding.types';
import { toAffectedUserEntities } from '../../../../../utils/entity-converter';

/**
 * Check for unconstrained delegation
 * UAC flag 0x80000 = TRUSTED_FOR_DELEGATION
 */
export function detectUnconstrainedDelegation(users: ADUser[], includeDetails: boolean): Finding {
  const affected = users.filter((u) => {
    if (!u.userAccountControl) return false;
    return (u.userAccountControl & 0x80000) !== 0;
  });

  return {
    type: 'UNCONSTRAINED_DELEGATION',
    severity: 'critical',
    category: 'kerberos',
    title: 'Unconstrained Delegation',
    description: 'User accounts with unconstrained Kerberos delegation enabled (UAC 0x80000). Can impersonate any user.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected) : undefined,
  };
}
