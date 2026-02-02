/**
 * Service Account No Preauth Detector
 * SERVICE_ACCOUNT_NO_PREAUTH: Service accounts without Kerberos pre-authentication
 * AS-REP Roasting target
 */

import { ADUser } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';
import { toAffectedUserEntities } from '../../../../../../utils/entity-converter';
import { isServiceAccount } from './utils';

export function detectServiceAccountNoPreauth(users: ADUser[], includeDetails: boolean): Finding {
  const DONT_REQUIRE_PREAUTH = 0x400000;

  const affected = users.filter((u) => {
    // Must be a service account
    if (!isServiceAccount(u)) return false;
    // Must be enabled
    if (!u.userAccountControl) return false;
    if ((u.userAccountControl & 0x2) !== 0) return false;
    // Check for "Do not require Kerberos preauthentication"
    return (u.userAccountControl & DONT_REQUIRE_PREAUTH) !== 0;
  });

  return {
    type: 'SERVICE_ACCOUNT_NO_PREAUTH',
    severity: 'high',
    category: 'accounts',
    title: 'Service Account Without Pre-Authentication (AS-REP Roasting)',
    description:
      'Service accounts with "Do not require Kerberos pre-authentication" enabled. Attackers can request AS-REP tickets and crack them offline.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected) : undefined,
    details:
      affected.length > 0
        ? {
            recommendation: 'Enable Kerberos pre-authentication for all service accounts.',
          }
        : undefined,
  };
}
