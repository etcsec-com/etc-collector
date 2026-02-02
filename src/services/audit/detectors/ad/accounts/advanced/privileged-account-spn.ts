/**
 * Privileged Account SPN Detector
 * Detect privileged accounts with SPNs (kerberoastable)
 * Admin accounts should NOT have SPNs as they become kerberoasting targets
 */

import { ADUser } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';
import { toAffectedUserEntities } from '../../../../../../utils/entity-converter';

export function detectPrivilegedAccountSpn(users: ADUser[], includeDetails: boolean): Finding {
  const affected = users.filter((u) => {
    // Must be privileged (adminCount=1)
    if (u.adminCount !== 1) return false;
    // Must be enabled
    if (!u.enabled) return false;

    // Must have SPN
    const spn = u['servicePrincipalName'];
    const hasSPN = spn && Array.isArray(spn) && spn.length > 0;

    return hasSPN;
  });

  return {
    type: 'PRIVILEGED_ACCOUNT_SPN',
    severity: 'high',
    category: 'accounts',
    title: 'Privileged Account with SPN',
    description:
      'Privileged accounts (adminCount=1) have Service Principal Names configured. These accounts are vulnerable to Kerberoasting attacks.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected) : undefined,
    details:
      affected.length > 0
        ? {
            attackVector: 'Request TGS ticket → Offline crack password → Full admin access',
            recommendation:
              'Remove SPNs from admin accounts. Use dedicated service accounts (preferably gMSA) for services.',
            criticalRisk: 'Compromising these accounts grants immediate Domain Admin or equivalent access.',
          }
        : undefined,
  };
}
