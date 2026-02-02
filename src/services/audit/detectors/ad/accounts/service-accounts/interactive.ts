/**
 * Service Account Interactive Detector
 * Detect service accounts with interactive logon capability
 * Service accounts should be denied interactive logon
 */

import { ADUser } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';
import { toAffectedUserEntities } from '../../../../../../utils/entity-converter';

export function detectServiceAccountInteractive(users: ADUser[], includeDetails: boolean): Finding {
  const affected = users.filter((u) => {
    // Must be a service account (has SPN or matches naming pattern)
    const spn = u['servicePrincipalName'];
    const hasSPN = spn && Array.isArray(spn) && spn.length > 0;
    const servicePatterns = [/^svc[_-]/i, /^sa[_-]/i, /service/i, /^sql/i, /^iis/i, /^app/i];
    const matchesPattern = servicePatterns.some((p) => p.test(u.sAMAccountName || ''));

    if (!hasSPN && !matchesPattern) return false;

    // Must be enabled
    if (!u.enabled) return false;

    // Check if interactive logon is NOT denied
    // A service account should have "Deny log on locally" and "Deny log on through RDP"
    // We check if the account has logged on recently (indicating interactive use)
    // or if it doesn't have restrictions that would prevent interactive logon

    // If the account has adminCount=0 (not protected by SDProp) and has recent logons
    // it's likely being used interactively
    const lastLogonStr = u.lastLogon;
    if (lastLogonStr) {
      const lastLogon = new Date(lastLogonStr);
      const daysSinceLogon = (Date.now() - lastLogon.getTime()) / (1000 * 60 * 60 * 24);
      // If logged on in last 30 days, may be used interactively
      if (daysSinceLogon < 30) {
        return true;
      }
    }

    // Also flag if password is set to never expire but account can logon interactively
    const pwdNeverExpires = u.userAccountControl ? (u.userAccountControl & 0x10000) !== 0 : false;
    const notDelegated = u.userAccountControl ? (u.userAccountControl & 0x100000) !== 0 : false;

    // Service accounts with password never expires but NOT marked as "not delegated" are risky
    return pwdNeverExpires && !notDelegated;
  });

  return {
    type: 'SERVICE_ACCOUNT_INTERACTIVE',
    severity: 'high',
    category: 'accounts',
    title: 'Service Account with Interactive Logon',
    description:
      'Service accounts appear to allow or use interactive logon. Service accounts should be restricted to service-only authentication.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected) : undefined,
    details:
      affected.length > 0
        ? {
            recommendation:
              'Apply "Deny log on locally" and "Deny log on through Remote Desktop Services" rights. Use gMSA where possible.',
            risks: [
              'Interactive sessions leave credentials in memory (mimikatz target)',
              'Increases attack surface for credential theft',
              'May indicate misuse of service accounts',
            ],
          }
        : undefined,
  };
}
