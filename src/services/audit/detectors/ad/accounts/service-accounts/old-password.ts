/**
 * Service Account Old Password Detector
 * SERVICE_ACCOUNT_OLD_PASSWORD: Service accounts with old passwords
 * High risk - service account passwords should be rotated regularly
 */

import { ADUser } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';
import { toAffectedUserEntities } from '../../../../../../utils/entity-converter';
import { isServiceAccount } from './utils';

export function detectServiceAccountOldPassword(users: ADUser[], includeDetails: boolean): Finding {
  const now = Date.now();
  const oneYearAgo = now - 365 * 24 * 60 * 60 * 1000;

  const affected = users.filter((u) => {
    // Must be a service account
    if (!isServiceAccount(u)) return false;
    // Must be enabled
    if (u.userAccountControl && (u.userAccountControl & 0x2) !== 0) return false;
    // Password must be older than 1 year
    if (!u.passwordLastSet) return true; // Never set = very old
    return u.passwordLastSet.getTime() < oneYearAgo;
  });

  return {
    type: 'SERVICE_ACCOUNT_OLD_PASSWORD',
    severity: 'high',
    category: 'accounts',
    title: 'Service Account with Old Password',
    description:
      'Service accounts with passwords not changed in over 1 year. These accounts are high-value targets and passwords should be rotated regularly.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected) : undefined,
    details:
      affected.length > 0
        ? {
            recommendation:
              'Rotate service account passwords every 90 days or migrate to gMSA for automatic password management.',
          }
        : undefined,
  };
}
