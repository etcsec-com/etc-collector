/**
 * ESC7: Vulnerable CA ACL
 *
 * Non-admin can manage CA (ManageCA or ManageCertificates rights).
 * Requires ACL parsing.
 */

import { Finding } from '../../../../../types/finding.types';
import { ADCSCertificateAuthority } from '../../../../../types/adcs.types';

/**
 * Detect ESC7: Vulnerable CA ACL
 * Non-admin can manage CA (ManageCA or ManageCertificates rights)
 * Note: Requires ACL parsing
 */
export function detectEsc7CaVulnerableAcl(
  cas: ADCSCertificateAuthority[],
  includeDetails: boolean
): Finding {
  // Would analyze nTSecurityDescriptor on CA enrollment objects for:
  // - ManageCA right
  // - ManageCertificates right
  // granted to non-admin principals

  return {
    type: 'ESC7_CA_VULNERABLE_ACL',
    severity: 'high',
    category: 'adcs',
    title: 'ESC7 - CA ACL Review Required',
    description:
      'Certificate Authority ACLs should be reviewed for ManageCA or ManageCertificates rights granted to non-administrators.',
    count: 0, // Placeholder until ACL analysis implemented
    affectedEntities: includeDetails ? cas.map((ca) => ca.name || ca.dn) : undefined,
    details: {
      note: 'Manual review of CA ACLs recommended.',
      casToReview: cas.length,
    },
  };
}
