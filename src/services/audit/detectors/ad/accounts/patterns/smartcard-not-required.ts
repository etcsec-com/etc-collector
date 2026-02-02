/**
 * Smartcard Not Required Detector
 * Check for accounts without smartcard requirement
 *
 * Detects enabled user accounts that don't have SMARTCARD_REQUIRED flag set.
 * In high-security environments, critical accounts should require smartcard.
 *
 * Note: This is a broad check. For admin-specific detection, use ADMIN_NO_SMARTCARD.
 * UAC flag 0x40000 = SMARTCARD_REQUIRED
 */

import { ADUser } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';
import { toAffectedUserEntities } from '../../../../../../utils/entity-converter';

export function detectSmartcardNotRequired(users: ADUser[], includeDetails: boolean): Finding {
  // Only check enabled accounts with adminCount=1 (privileged accounts)
  // Regular users without smartcard is expected in most environments
  const affected = users.filter((u) => {
    if (!u.enabled) return false;
    if (!u.adminCount || u.adminCount !== 1) return false;

    const uac = u.userAccountControl || 0;
    // Check if SMARTCARD_REQUIRED is NOT set
    return (uac & 0x40000) === 0;
  });

  return {
    type: 'SMARTCARD_NOT_REQUIRED',
    severity: 'medium',
    category: 'accounts',
    title: 'Smartcard Not Required',
    description:
      'Privileged accounts (adminCount=1) without smartcard requirement. ' +
      'High-value accounts should require strong authentication.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected) : undefined,
  };
}
