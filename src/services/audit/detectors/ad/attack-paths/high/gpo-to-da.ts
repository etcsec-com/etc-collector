/**
 * GPO to Domain Admin Path Detector
 *
 * Detects GPO modification paths to Domain Admin.
 * Non-admins who can modify GPOs applied to privileged users/computers.
 */

import { AclEntry } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';
import { ADGPO } from '../../../../../../types/gpo.types';

/**
 * Detect GPO modification paths to Domain Admin
 * Non-admins who can modify GPOs applied to privileged users/computers
 */
export function detectPathGpoToDA(
  gpos: ADGPO[],
  aclEntries: AclEntry[],
  includeDetails: boolean
): Finding {
  // Find GPOs with weak ACLs (non-admin can modify)
  const adminSids = [
    'S-1-5-32-544', // Administrators
    'S-1-5-21-*-512', // Domain Admins pattern
    'S-1-5-21-*-519', // Enterprise Admins pattern
  ];

  const vulnerableGpos: ADGPO[] = [];

  for (const gpo of gpos) {
    // Find ACLs for this GPO
    const gpoAcls = aclEntries.filter((acl) => acl.objectDn.toLowerCase() === gpo.dn.toLowerCase());

    // Check for dangerous write permissions from non-admin principals
    const hasWeakAcl = gpoAcls.some((acl) => {
      const isAdmin = adminSids.some((pattern) => {
        if (pattern.includes('*')) {
          const regex = new RegExp(pattern.replace('*', '.*'));
          return regex.test(acl.trustee);
        }
        return acl.trustee === pattern;
      });

      // Has write permission but not an admin
      const hasWrite = (acl.accessMask & 0x40000000) !== 0 || (acl.accessMask & 0x10000000) !== 0;
      // aceType is string '0' for ACCESS_ALLOWED_ACE_TYPE
      return hasWrite && !isAdmin && String(acl.aceType) === '0';
    });

    if (hasWeakAcl) {
      vulnerableGpos.push(gpo);
    }
  }

  return {
    type: 'PATH_GPO_TO_DA',
    severity: 'critical',
    category: 'attack-paths',
    title: 'GPO Modification Path to Domain Admin',
    description:
      'GPOs can be modified by non-admin users. If these GPOs apply to privileged users or DCs, attackers can achieve Domain Admin.',
    count: vulnerableGpos.length,
    affectedEntities: includeDetails ? vulnerableGpos.map((g) => g.dn) : undefined,
    details:
      vulnerableGpos.length > 0
        ? {
            vulnerableGpos: vulnerableGpos.map((g) => g.displayName || g.cn),
            attackVector: 'Modify GPO → Add malicious script/scheduled task → Execute on DA logon',
            mitigation: 'Restrict GPO modification rights, implement GPO change monitoring',
          }
        : undefined,
  };
}
