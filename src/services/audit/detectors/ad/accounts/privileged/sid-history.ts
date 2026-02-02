/**
 * SID History Detector
 * Check for SID history attribute
 * Note: LDAP attribute name can vary in case (sIDHistory, sidhistory, etc.)
 */

import { ADUser } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';
import { toAffectedUserEntities } from '../../../../../../utils/entity-converter';

export function detectSidHistory(users: ADUser[], includeDetails: boolean): Finding {
  const affected = users.filter((u) => {
    // Check multiple possible attribute names (case-insensitive)
    const userObj = u as Record<string, unknown>;
    const sidHistory =
      userObj['sIDHistory'] ??
      userObj['sidhistory'] ??
      userObj['SIDHistory'] ??
      userObj['sidHistory'];

    // Check if attribute exists and has value
    if (!sidHistory) return false;

    // Handle array or single value
    if (Array.isArray(sidHistory)) {
      return sidHistory.length > 0;
    }
    return !!sidHistory;
  });

  return {
    type: 'SID_HISTORY',
    severity: 'high',
    category: 'accounts',
    title: 'SID History Present',
    description: 'User accounts with sIDHistory attribute. Can be abused for privilege escalation.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected) : undefined,
  };
}
