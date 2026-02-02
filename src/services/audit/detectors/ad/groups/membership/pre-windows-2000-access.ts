/**
 * PRE_WINDOWS_2000_ACCESS - Pre-Windows 2000 Compatible Access membership
 */

import { ADUser } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';
import { toAffectedUserEntities } from '../../../../../../utils/entity-converter';

/**
 * Check for Pre-Windows 2000 Compatible Access membership
 */
export function detectPreWindows2000Access(users: ADUser[], includeDetails: boolean): Finding {
  const affected = users.filter((u) => {
    if (!u.memberOf) return false;
    return u.memberOf.some((dn) => dn.includes('CN=Pre-Windows 2000 Compatible Access'));
  });

  return {
    type: 'PRE_WINDOWS_2000_ACCESS',
    severity: 'medium',
    category: 'groups',
    title: 'Pre-Windows 2000 Compatible Access',
    description: 'Pre-Windows 2000 Compatible Access group has members. Overly permissive read access to AD objects.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected) : undefined,
  };
}
