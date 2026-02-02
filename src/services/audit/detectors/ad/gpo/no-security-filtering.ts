/**
 * GPO_NO_SECURITY_FILTERING - GPO without explicit security filtering
 */

import { Finding } from '../../../../../types/finding.types';
import { ADGPO, GPOLink, GPOAclEntry } from '../../../../../types/gpo.types';
import {
  SID_AUTHENTICATED_USERS,
  SID_EVERYONE,
  SID_DOMAIN_COMPUTERS,
  APPLY_GROUP_POLICY_RIGHT,
} from './types';

/**
 * GPO_NO_SECURITY_FILTERING: GPO without explicit security filtering
 * GPO applies to all objects in the linked OU without restrictions
 */
export function detectGpoNoSecurityFiltering(
  gpos: ADGPO[],
  links: GPOLink[],
  gpoAcls: GPOAclEntry[],
  includeDetails: boolean
): Finding {
  // Get linked GPO GUIDs
  const linkedGuids = new Set(
    links.filter((l) => !l.disabled).map((l) => l.gpoGuid.toLowerCase())
  );

  // Find GPOs that are linked but have no security filtering
  // Security filtering = only specific groups have "Apply Group Policy" right
  // No filtering = Authenticated Users or Everyone has Apply right
  const noFiltering: ADGPO[] = [];

  for (const gpo of gpos) {
    // Only check linked GPOs
    if (!linkedGuids.has(gpo.cn.toLowerCase())) continue;

    // Get ACLs for this GPO
    const aclsForGpo = gpoAcls.filter(
      (acl) => acl.gpoDn.toLowerCase() === gpo.dn.toLowerCase()
    );

    // If no ACL data, skip (can't determine)
    if (aclsForGpo.length === 0) continue;

    // Check if Authenticated Users or Everyone has Apply permission
    const hasUnrestrictedApply = aclsForGpo.some(
      (acl) =>
        (acl.trusteeSid === SID_AUTHENTICATED_USERS || acl.trusteeSid === SID_EVERYONE) &&
        (acl.accessMask & APPLY_GROUP_POLICY_RIGHT) !== 0
    );

    // Check if there's any specific group filtering (exclude auth users and everyone)
    const hasSpecificFiltering = aclsForGpo.some(
      (acl) =>
        acl.trusteeSid !== SID_AUTHENTICATED_USERS &&
        acl.trusteeSid !== SID_EVERYONE &&
        !acl.trusteeSid.endsWith(SID_DOMAIN_COMPUTERS) &&
        (acl.accessMask & APPLY_GROUP_POLICY_RIGHT) !== 0
    );

    // No filtering if auth users/everyone can apply and no specific groups defined
    if (hasUnrestrictedApply && !hasSpecificFiltering) {
      noFiltering.push(gpo);
    }
  }

  return {
    type: 'GPO_NO_SECURITY_FILTERING',
    severity: 'medium',
    category: 'gpo',
    title: 'GPO Without Security Filtering',
    description:
      'GPOs that apply to all Authenticated Users or Everyone without specific security filtering. Consider restricting GPO application to specific groups.',
    count: noFiltering.length,
    affectedEntities: includeDetails
      ? noFiltering.map((gpo) => gpo.displayName || gpo.cn)
      : undefined,
    details:
      noFiltering.length > 0
        ? {
            recommendation:
              'Apply security filtering to restrict GPO application to specific groups.',
          }
        : undefined,
  };
}
