/**
 * Constrained Delegation Detector
 *
 * Detects user accounts with constrained Kerberos delegation configured.
 * UAC flag 0x1000000 = TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION
 */

import { ADUser } from '../../../../../types/ad.types';
import { Finding } from '../../../../../types/finding.types';
import { toAffectedUserEntities } from '../../../../../utils/entity-converter';

/**
 * Check for constrained delegation
 * UAC flag 0x1000000 = TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION
 */
export function detectConstrainedDelegation(users: ADUser[], includeDetails: boolean): Finding {
  const affected = users.filter((u) => {
    if (!u.userAccountControl) return false;
    return (u.userAccountControl & 0x1000000) !== 0;
  });

  return {
    type: 'CONSTRAINED_DELEGATION',
    severity: 'high',
    category: 'kerberos',
    title: 'Constrained Delegation',
    description: 'User accounts with constrained Kerberos delegation configured (UAC 0x1000000). Can impersonate users to specific services.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected) : undefined,
  };
}
