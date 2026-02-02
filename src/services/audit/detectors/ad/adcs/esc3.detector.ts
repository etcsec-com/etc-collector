/**
 * ESC3: Enrollment Agent Certificate Template
 *
 * Template allows Certificate Request Agent (enrollment agent) certificates.
 * These can be used to enroll certificates on behalf of other users.
 */

import { Finding } from '../../../../../types/finding.types';
import {
  ADCSCertificateTemplate,
  CT_FLAG_PEND_ALL_REQUESTS,
  EKU_CERTIFICATE_REQUEST_AGENT,
} from '../../../../../types/adcs.types';

/**
 * Detect ESC3: Enrollment Agent Certificate Template
 * Template allows Certificate Request Agent (enrollment agent) certificates
 */
export function detectEsc3EnrollmentAgent(
  templates: ADCSCertificateTemplate[],
  includeDetails: boolean
): Finding {
  const affected = templates.filter((t) => {
    const ekus = t.pKIExtendedKeyUsage || [];
    const enrollmentFlag = t['msPKI-Enrollment-Flag'] || 0;

    // Has Certificate Request Agent EKU
    const hasEnrollmentAgent = ekus.includes(EKU_CERTIFICATE_REQUEST_AGENT);

    // Doesn't require manager approval
    const noApprovalRequired = (enrollmentFlag & CT_FLAG_PEND_ALL_REQUESTS) === 0;

    return hasEnrollmentAgent && noApprovalRequired;
  });

  return {
    type: 'ESC3_ENROLLMENT_AGENT',
    severity: 'high',
    category: 'adcs',
    title: 'ESC3 - Enrollment Agent Certificate Template',
    description:
      'Certificate template allows issuance of enrollment agent certificates, which can be used to enroll certificates on behalf of other users.',
    count: affected.length,
    affectedEntities: includeDetails ? affected.map((t) => t.name || t.displayName || t.dn) : undefined,
  };
}
