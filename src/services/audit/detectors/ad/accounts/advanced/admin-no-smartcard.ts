/**
 * Admin No Smartcard Detector
 * Detect admin accounts without smartcard requirement
 * Privileged accounts should require smartcard authentication
 */

import { ADUser } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';
import { toAffectedUserEntities } from '../../../../../../utils/entity-converter';

export function detectAdminNoSmartcard(users: ADUser[], includeDetails: boolean): Finding {
  const affected = users.filter((u) => {
    // Must be privileged (adminCount=1)
    if (u.adminCount !== 1) return false;
    // Must be enabled
    if (!u.enabled) return false;

    // Check SMARTCARD_REQUIRED flag (0x40000)
    const smartcardRequired = u.userAccountControl ? (u.userAccountControl & 0x40000) !== 0 : false;

    return !smartcardRequired;
  });

  return {
    type: 'ADMIN_NO_SMARTCARD',
    severity: 'medium',
    category: 'accounts',
    title: 'Admin Account Without Smartcard Requirement',
    description:
      'Privileged accounts can authenticate with passwords instead of smartcards. Passwords are more vulnerable to theft and phishing.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected) : undefined,
    details:
      affected.length > 0
        ? {
            recommendation:
              'Enable "Smart card is required for interactive logon" for all admin accounts.',
            benefits: [
              'Eliminates password-based attacks (phishing, credential theft)',
              'Provides two-factor authentication',
              'Reduces risk of credential replay attacks',
            ],
          }
        : undefined,
  };
}
