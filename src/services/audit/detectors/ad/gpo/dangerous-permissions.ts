/**
 * GPO_DANGEROUS_PERMISSIONS - Non-admin can edit GPO
 */

import { Finding } from '../../../../../types/finding.types';
import { ADGPO, GPOLink } from '../../../../../types/gpo.types';

/**
 * GPO_DANGEROUS_PERMISSIONS: Non-admin can edit GPO
 * Note: Requires ACL analysis - placeholder for now
 */
export function detectGpoDangerousPermissions(
  gpos: ADGPO[],
  _links: GPOLink[],
  _includeDetails: boolean
): Finding {
  // Would analyze nTSecurityDescriptor on GPO objects for:
  // - GenericAll, GenericWrite, WriteDacl, WriteOwner, WriteProperty
  // granted to non-admin principals (Domain Users, Authenticated Users, etc.)

  return {
    type: 'GPO_DANGEROUS_PERMISSIONS',
    severity: 'high',
    category: 'gpo',
    title: 'GPO Permissions Review Required',
    description:
      'Group Policy Objects should be reviewed for overly permissive ACLs that allow non-administrators to modify GPO settings.',
    count: 0, // Placeholder until ACL analysis implemented
    affectedEntities: undefined,
    details: {
      note: 'Manual review of GPO ACLs recommended. Check for non-admin principals with write access.',
      gposToReview: gpos.length,
    },
  };
}
