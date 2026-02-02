/**
 * Service Account with SPN Detector
 * USER_ACCOUNT_WITH_SPN: User accounts with Service Principal Name
 * Kerberoasting targets - attackers can request service tickets and crack them offline
 */

import { ADUser } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';
import { toAffectedUserEntities } from '../../../../../../utils/entity-converter';
import { getServicePrincipalNames } from './utils';

export function detectServiceAccountWithSpn(users: ADUser[], includeDetails: boolean): Finding {
  const affected = users.filter((u) => {
    // Must be enabled and have SPN
    const spns = getServicePrincipalNames(u);
    if (spns.length === 0) return false;
    // Exclude disabled accounts
    if (u.userAccountControl && (u.userAccountControl & 0x2) !== 0) return false;
    return true;
  });

  return {
    type: 'SERVICE_ACCOUNT_WITH_SPN',
    severity: 'medium',
    category: 'accounts',
    title: 'Service Account with SPN (Kerberoasting Target)',
    description:
      'User accounts with Service Principal Name configured. These accounts are targets for Kerberoasting attacks where attackers request TGS tickets and crack them offline.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected) : undefined,
    details:
      affected.length > 0
        ? {
            recommendation:
              'Use gMSA (Group Managed Service Accounts) instead. For existing accounts, ensure strong passwords (25+ chars) and regular rotation.',
            spnCount: affected.reduce((sum, u) => sum + getServicePrincipalNames(u).length, 0),
          }
        : undefined,
  };
}
