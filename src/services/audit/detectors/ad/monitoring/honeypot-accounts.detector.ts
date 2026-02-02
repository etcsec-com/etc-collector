/**
 * Honeypot Accounts Detector
 *
 * Detects absence of honeypot/decoy accounts.
 * Honeypots help detect attackers early during enumeration.
 */

import { ADUser } from '../../../../../types/ad.types';
import { Finding } from '../../../../../types/finding.types';

/**
 * Detect absence of honeypot/decoy accounts
 * Honeypots help detect attackers early during enumeration
 */
export function detectNoHoneypotAccounts(users: ADUser[], _includeDetails: boolean): Finding {
  const honeypotPatterns = ['honeypot', 'decoy', 'trap', 'canary', 'bait', 'fake'];
  const attractivePatterns = ['svc_', 'admin_backup', 'admin_old', 'sa_', 'sqlsvc', 'backup_admin'];

  // Find explicit honeypot accounts
  const honeypots = users.filter((u) => {
    const rawDesc = u.description;
    const desc = (typeof rawDesc === 'string' ? rawDesc : '').toLowerCase();
    const name = (u.sAMAccountName || '').toLowerCase();
    return honeypotPatterns.some((p) => desc.includes(p) || name.includes(p));
  });

  // Find potential bait accounts (attractive names, never used)
  const potentialBaits = users.filter((u) => {
    const name = (u.sAMAccountName || '').toLowerCase();
    const hasAttractiveNaming = attractivePatterns.some((p) => name.includes(p));
    const neverLoggedIn = !u.lastLogon;
    const isEnabled = u.enabled;
    return hasAttractiveNaming && neverLoggedIn && isEnabled;
  });

  const hasHoneypots = honeypots.length > 0 || potentialBaits.length >= 2;

  return {
    type: 'NO_HONEYPOT_ACCOUNTS',
    severity: 'medium',
    category: 'monitoring',
    title: 'No Honeypot/Decoy Accounts Detected',
    description:
      'No honeypot or decoy accounts detected in the directory. These accounts help detect attackers during enumeration phase.',
    count: hasHoneypots ? 0 : 1,
    affectedEntities: undefined, // No affected entities - this is a missing control
    details: hasHoneypots
      ? {
          honeypotCount: honeypots.length,
          potentialBaitCount: potentialBaits.length,
          status: 'Honeypot accounts detected',
        }
      : {
          recommendation:
            'Create honeypot accounts with attractive names (e.g., svc_backup, admin_old) and monitor for any usage.',
          benefits: [
            'Early detection of attacker enumeration',
            'Detect credential stuffing attempts',
            'Alert on lateral movement',
          ],
          implementationGuide:
            'Create accounts with attractive names but no real permissions. Alert on any authentication attempt.',
        },
  };
}
