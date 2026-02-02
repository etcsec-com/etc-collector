/**
 * Service Account Naming Detector
 * SERVICE_ACCOUNT_NAMING: Accounts matching service naming conventions
 */

import { ADUser } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';
import { toAffectedUserEntities } from '../../../../../../utils/entity-converter';
import { SERVICE_ACCOUNT_PATTERNS, getServicePrincipalNames } from './utils';

export function detectServiceAccountNaming(users: ADUser[], includeDetails: boolean): Finding {
  const affected = users.filter((u) => {
    // Only accounts matching naming patterns but WITHOUT SPN
    // (accounts WITH SPN are covered by SERVICE_ACCOUNT_WITH_SPN)
    const spns = getServicePrincipalNames(u);
    if (spns.length > 0) return false;
    // Exclude disabled accounts
    if (u.userAccountControl && (u.userAccountControl & 0x2) !== 0) return false;
    return SERVICE_ACCOUNT_PATTERNS.some((pattern) => pattern.test(u.sAMAccountName));
  });

  return {
    type: 'SERVICE_ACCOUNT_NAMING',
    severity: 'low',
    category: 'accounts',
    title: 'Service Account by Naming Convention',
    description:
      'User accounts matching service account naming patterns (svc_, _svc, service, etc.) without SPN. Review if these are actual service accounts.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected) : undefined,
  };
}
