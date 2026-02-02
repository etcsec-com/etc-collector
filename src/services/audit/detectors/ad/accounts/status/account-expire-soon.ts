/**
 * Account Expire Soon Detector
 * Check for accounts expiring within 30 days
 * Useful for proactive account management
 */

import { ADUser } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';
import { toAffectedUserEntities } from '../../../../../../utils/entity-converter';
import { filetimeToDate } from './utils';

export function detectAccountExpireSoon(users: ADUser[], includeDetails: boolean): Finding {
  const now = Date.now();
  const thirtyDaysFromNow = now + 30 * 24 * 60 * 60 * 1000;

  const affected = users.filter((u) => {
    // Must be enabled
    if (!u.enabled) return false;
    // Check accountExpires
    const expiresDate = filetimeToDate(u.accountExpires);
    if (!expiresDate) return false; // Never expires
    // Expiring within 30 days but not already expired
    return expiresDate.getTime() > now && expiresDate.getTime() <= thirtyDaysFromNow;
  });

  return {
    type: 'ACCOUNT_EXPIRE_SOON',
    severity: 'medium',
    category: 'accounts',
    title: 'Account Expiring Soon',
    description:
      'User accounts set to expire within the next 30 days. Review if these expirations are intentional or if accounts need to be extended.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected) : undefined,
  };
}
