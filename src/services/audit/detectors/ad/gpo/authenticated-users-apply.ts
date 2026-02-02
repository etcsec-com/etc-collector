/**
 * GPO_AUTHENTICATED_USERS_APPLY - GPO explicitly grants Apply to Authenticated Users
 */

import { Finding } from '../../../../../types/finding.types';
import { ADGPO, GPOLink, GPOAclEntry } from '../../../../../types/gpo.types';
import { SID_AUTHENTICATED_USERS, APPLY_GROUP_POLICY_RIGHT } from './types';

/**
 * GPO_AUTHENTICATED_USERS_APPLY: GPO explicitly grants Apply to Authenticated Users
 * This is the default but may be unintended for sensitive GPOs
 */
export function detectGpoAuthenticatedUsersApply(
  gpos: ADGPO[],
  links: GPOLink[],
  gpoAcls: GPOAclEntry[],
  includeDetails: boolean
): Finding {
  // Get linked GPO GUIDs
  const linkedGuids = new Set(
    links.filter((l) => !l.disabled).map((l) => l.gpoGuid.toLowerCase())
  );

  // Find GPOs where Authenticated Users has explicit Apply permission
  const authUsersApply: ADGPO[] = [];

  for (const gpo of gpos) {
    // Only check linked GPOs
    if (!linkedGuids.has(gpo.cn.toLowerCase())) continue;

    // Get ACLs for this GPO
    const aclsForGpo = gpoAcls.filter(
      (acl) => acl.gpoDn.toLowerCase() === gpo.dn.toLowerCase()
    );

    // If no ACL data, skip
    if (aclsForGpo.length === 0) continue;

    // Check if Authenticated Users specifically has Apply permission
    const authUsersHasApply = aclsForGpo.some(
      (acl) =>
        acl.trusteeSid === SID_AUTHENTICATED_USERS &&
        (acl.accessMask & APPLY_GROUP_POLICY_RIGHT) !== 0
    );

    if (authUsersHasApply) {
      authUsersApply.push(gpo);
    }
  }

  return {
    type: 'GPO_AUTHENTICATED_USERS_APPLY',
    severity: 'medium',
    category: 'gpo',
    title: 'GPO Applies to All Authenticated Users',
    description:
      'GPOs with Authenticated Users granted the "Apply Group Policy" permission. This is the default but may be too broad for sensitive policies.',
    count: authUsersApply.length,
    affectedEntities: includeDetails
      ? authUsersApply.map((gpo) => gpo.displayName || gpo.cn)
      : undefined,
    details:
      authUsersApply.length > 0
        ? {
            recommendation:
              'Review if all GPOs should apply to all users. Consider using security filtering for sensitive policies.',
            note: 'This is informational - Authenticated Users is the default.',
          }
        : undefined,
  };
}
