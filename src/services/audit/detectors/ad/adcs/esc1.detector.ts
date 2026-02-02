/**
 * ESC1: Misconfigured Certificate Template
 *
 * Template allows enrollee to supply subject AND has client authentication EKU.
 * This enables privilege escalation to any user/computer.
 */

import { Finding } from '../../../../../types/finding.types';
import {
  ADCSCertificateTemplate,
  CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT,
  CT_FLAG_PEND_ALL_REQUESTS,
} from '../../../../../types/adcs.types';
import { hasAuthenticationEku } from './utils';

/**
 * Detect ESC1: Misconfigured Certificate Template
 * Template allows enrollee to supply subject AND has client authentication EKU
 */
export function detectEsc1VulnerableTemplate(
  templates: ADCSCertificateTemplate[],
  includeDetails: boolean
): Finding {
  const affected = templates.filter((t) => {
    const nameFlag = t['msPKI-Certificate-Name-Flag'] || 0;
    const enrollmentFlag = t['msPKI-Enrollment-Flag'] || 0;
    const ekus = t.pKIExtendedKeyUsage || [];

    // Enrollee can supply subject
    const enrolleeSuppliesSubject = (nameFlag & CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT) !== 0;

    // Has authentication capability
    const canAuthenticate = hasAuthenticationEku(ekus);

    // Doesn't require manager approval
    const noApprovalRequired = (enrollmentFlag & CT_FLAG_PEND_ALL_REQUESTS) === 0;

    return enrolleeSuppliesSubject && canAuthenticate && noApprovalRequired;
  });

  return {
    type: 'ESC1_VULNERABLE_TEMPLATE',
    severity: 'critical',
    category: 'adcs',
    title: 'ESC1 - Misconfigured Certificate Template',
    description:
      'Certificate template allows enrollee to specify Subject Alternative Name (SAN) and has client authentication EKU, enabling privilege escalation to any user/computer.',
    count: affected.length,
    affectedEntities: includeDetails ? affected.map((t) => t.name || t.displayName || t.dn) : undefined,
  };
}
