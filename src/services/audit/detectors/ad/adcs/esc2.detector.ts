/**
 * ESC2: Any Purpose Certificate Template
 *
 * Template has "Any Purpose" EKU or SubCA capability.
 * Allows issued certificates to be used for any purpose including client authentication.
 */

import { Finding } from '../../../../../types/finding.types';
import {
  ADCSCertificateTemplate,
  CT_FLAG_PEND_ALL_REQUESTS,
  EKU_ANY_PURPOSE,
} from '../../../../../types/adcs.types';

/**
 * Detect ESC2: Any Purpose Certificate Template
 * Template has "Any Purpose" EKU or SubCA capability
 */
export function detectEsc2AnyPurpose(
  templates: ADCSCertificateTemplate[],
  includeDetails: boolean
): Finding {
  const affected = templates.filter((t) => {
    const ekus = t.pKIExtendedKeyUsage || [];
    const enrollmentFlag = t['msPKI-Enrollment-Flag'] || 0;

    // Has "Any Purpose" EKU
    const hasAnyPurpose = ekus.includes(EKU_ANY_PURPOSE);

    // No EKU constraint (implies any purpose)
    const noEkuConstraint = ekus.length === 0;

    // Doesn't require manager approval
    const noApprovalRequired = (enrollmentFlag & CT_FLAG_PEND_ALL_REQUESTS) === 0;

    return (hasAnyPurpose || noEkuConstraint) && noApprovalRequired;
  });

  return {
    type: 'ESC2_ANY_PURPOSE',
    severity: 'high',
    category: 'adcs',
    title: 'ESC2 - Any Purpose Certificate Template',
    description:
      'Certificate template has "Any Purpose" EKU or no EKU constraints, allowing issued certificates to be used for any purpose including client authentication.',
    count: affected.length,
    affectedEntities: includeDetails ? affected.map((t) => t.name || t.displayName || t.dn) : undefined,
  };
}
