/**
 * AS-REP Roasting Risk Detector
 *
 * Detects user accounts without Kerberos pre-authentication required.
 * UAC flag 0x400000 = DONT_REQ_PREAUTH
 */

import { ADUser } from '../../../../../types/ad.types';
import { Finding } from '../../../../../types/finding.types';
import { toAffectedUserEntities } from '../../../../../utils/entity-converter';

/**
 * Check for ASREP roasting risk (no Kerberos pre-authentication)
 * UAC flag 0x400000 = DONT_REQ_PREAUTH
 */
export function detectAsrepRoastingRisk(users: ADUser[], includeDetails: boolean): Finding {
  const affected = users.filter((u) => {
    if (!u.userAccountControl) return false;
    return (u.userAccountControl & 0x400000) !== 0;
  });

  return {
    type: 'ASREP_ROASTING_RISK',
    severity: 'critical',
    category: 'kerberos',
    title: 'AS-REP Roasting Risk',
    description: 'User accounts without Kerberos pre-authentication required (UAC 0x400000). Vulnerable to AS-REP roasting attacks.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected) : undefined,
  };
}
