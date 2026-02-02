/**
 * Stale Account Detector
 * Check for stale accounts (180+ days inactive)
 * PingCastle: StaleAccount
 */

import { ADUser } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';
import { toAffectedUserEntities } from '../../../../../../utils/entity-converter';

export function detectStaleAccount(users: ADUser[], includeDetails: boolean): Finding {
  const now = Date.now();
  const sixMonthsAgo = now - 180 * 24 * 60 * 60 * 1000;

  const affected = users.filter((u) => {
    // Must be enabled
    if (!u.enabled) return false;
    // Check if last logon is older than 180 days
    if (!u.lastLogon) return false;
    const lastLogonTime = u.lastLogon instanceof Date ? u.lastLogon.getTime() : new Date(u.lastLogon).getTime();
    if (isNaN(lastLogonTime)) return false;
    return lastLogonTime < sixMonthsAgo;
  });

  return {
    type: 'STALE_ACCOUNT',
    severity: 'high',
    category: 'accounts',
    title: 'Stale Account (180+ Days)',
    description: 'Enabled user accounts inactive for 180+ days. Stale accounts increase attack surface and should be reviewed.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected) : undefined,
  };
}
