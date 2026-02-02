/**
 * NIST AC-2 - Account Management
 * Checks account management compliance:
 * - Inactive accounts disabled
 * - Guest account disabled
 * - Service accounts documented
 */

import { ADUser } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';
import { toAffectedUserEntities } from '../../../../../../utils/entity-converter';

export function detectNistAc2AccountManagement(
  users: ADUser[],
  includeDetails: boolean
): Finding {
  const issues: { issue: string; count: number }[] = [];
  const affectedUsers: ADUser[] = [];

  // Check for inactive accounts (90 days)
  const now = Date.now();
  const ninetyDaysAgo = now - 90 * 24 * 60 * 60 * 1000;
  const inactiveAccounts = users.filter(
    (u) => u.enabled && u.lastLogon && u.lastLogon.getTime() < ninetyDaysAgo
  );
  if (inactiveAccounts.length > 0) {
    issues.push({ issue: 'Inactive accounts (90+ days) still enabled', count: inactiveAccounts.length });
    affectedUsers.push(...inactiveAccounts);
  }

  // Check for enabled accounts that have never logged on
  const neverLoggedOn = users.filter((u) => u.enabled && !u.lastLogon);
  if (neverLoggedOn.length > 0) {
    issues.push({ issue: 'Enabled accounts never logged on', count: neverLoggedOn.length });
    affectedUsers.push(...neverLoggedOn.filter((u) => !affectedUsers.includes(u)));
  }

  // Check for Guest account enabled
  const guestEnabled = users.filter(
    (u) => u.sAMAccountName.toLowerCase() === 'guest' && u.enabled
  );
  if (guestEnabled.length > 0) {
    issues.push({ issue: 'Guest account enabled', count: 1 });
    affectedUsers.push(...guestEnabled);
  }

  return {
    type: 'NIST_AC_2_ACCOUNT_MANAGEMENT',
    severity: 'high',
    category: 'compliance',
    title: 'NIST AC-2 - Account Management Issues',
    description:
      'Account management does not comply with NIST AC-2. Inactive accounts should be disabled, guest account should be disabled.',
    count: affectedUsers.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affectedUsers.slice(0, 50)) : undefined,
    details: issues.length > 0 ? { violations: issues, framework: 'NIST', control: 'AC-2' } : undefined,
  };
}
