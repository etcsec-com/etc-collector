/**
 * Never Logged On Detector
 * Check for enabled accounts that have never logged on
 * Indicates orphaned, unused, or provisioning issues
 */

import { ADUser } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';
import { toAffectedUserEntities } from '../../../../../../utils/entity-converter';

export function detectNeverLoggedOn(users: ADUser[], includeDetails: boolean): Finding {
  const affected = users.filter((u) => {
    // Must be enabled
    if (!u.enabled) return false;
    // Never logged on
    return !u.lastLogon;
  });

  return {
    type: 'NEVER_LOGGED_ON',
    severity: 'medium',
    category: 'accounts',
    title: 'Never Logged On',
    description:
      'Enabled user accounts that have never logged into the domain. May indicate orphaned accounts, provisioning issues, or unused accounts that should be disabled.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected) : undefined,
  };
}
