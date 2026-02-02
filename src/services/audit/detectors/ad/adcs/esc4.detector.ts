/**
 * ESC4: Vulnerable Certificate Template ACL
 *
 * Low-privileged users can modify template properties.
 * Requires ACL parsing - simplified version checks if template has security descriptor.
 */

import { Finding } from '../../../../../types/finding.types';
import { ADCSCertificateTemplate } from '../../../../../types/adcs.types';
import { hasAuthenticationEku } from './utils';

/**
 * Detect ESC4: Vulnerable Certificate Template ACL
 * Low-privileged users can modify template properties
 * Note: Requires ACL parsing - simplified version checks if template has security descriptor
 */
export function detectEsc4VulnerableTemplateAcl(
  templates: ADCSCertificateTemplate[],
  _includeDetails: boolean
): Finding {
  // In a full implementation, this would parse nTSecurityDescriptor and check for
  // GenericAll, GenericWrite, WriteDacl, WriteOwner, or WriteProperty rights
  // for non-admin principals

  // For now, we flag templates that have authentication capability
  // and mark them as needing manual ACL review
  const affected = templates.filter((t) => {
    const ekus = t.pKIExtendedKeyUsage || [];
    return hasAuthenticationEku(ekus) && t.nTSecurityDescriptor !== undefined;
  });

  // This is a placeholder - actual implementation would analyze ACLs
  return {
    type: 'ESC4_VULNERABLE_TEMPLATE_ACL',
    severity: 'critical',
    category: 'adcs',
    title: 'ESC4 - Certificate Template ACL Review Required',
    description:
      'Certificate templates with authentication capability should be reviewed for overly permissive ACLs that allow non-admins to modify template properties.',
    count: 0, // Set to 0 until actual ACL analysis is implemented
    affectedEntities: undefined,
    details: {
      note: 'Full ACL analysis requires parsing nTSecurityDescriptor. Manual review recommended.',
      templatesWithAuthEku: affected.length,
    },
  };
}
