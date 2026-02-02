/**
 * Shared Account Detector
 * Check for shared accounts
 */

import { ADUser } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';
import { toAffectedUserEntities } from '../../../../../../utils/entity-converter';

export function detectSharedAccount(users: ADUser[], includeDetails: boolean): Finding {
  const sharedPatterns = [/^shared/i, /^common/i, /^generic/i, /^service/i, /^svc/i];

  const affected = users.filter((u) => {
    return sharedPatterns.some((pattern) => pattern.test(u.sAMAccountName));
  });

  return {
    type: 'SHARED_ACCOUNT',
    severity: 'medium',
    category: 'accounts',
    title: 'Shared Account',
    description: 'User accounts with shared/generic naming. Prevents proper accountability.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected) : undefined,
  };
}
