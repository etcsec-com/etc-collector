/**
 * Domain Admin in Description Detector
 * Check for domain admin keywords in description
 */

import { ADUser } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';
import { toAffectedUserEntities, ldapAttrToString } from '../../../../../../utils/entity-converter';

export function detectDomainAdminInDescription(users: ADUser[], includeDetails: boolean): Finding {
  const sensitiveKeywords = [
    /domain\s*admin/i,
    /enterprise\s*admin/i,
    /administrator/i,
    /admin\s*account/i,
    /privileged/i,
  ];

  const affected = users.filter((u) => {
    const description = ldapAttrToString((u as any)['description']);
    if (!description) return false;
    return sensitiveKeywords.some((pattern) => pattern.test(description));
  });

  return {
    type: 'DOMAIN_ADMIN_IN_DESCRIPTION',
    severity: 'high',
    category: 'accounts',
    title: 'Sensitive Terms in Description',
    description: 'User accounts with admin/privileged keywords in description field. Information disclosure.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected) : undefined,
  };
}
