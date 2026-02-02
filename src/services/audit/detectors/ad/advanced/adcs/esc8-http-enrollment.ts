/**
 * ESC8 HTTP Enrollment Detector
 * Check for ESC8 HTTP enrollment
 */

import { Finding } from '../../../../../../types/finding.types';

export function detectEsc8HttpEnrollment(cas: any[], includeDetails: boolean): Finding {
  const affected = cas.filter((ca) => {
    return ca.webEnrollment && ca.webEnrollment.protocol === 'http';
  });

  return {
    type: 'ESC8_HTTP_ENROLLMENT',
    severity: 'medium',
    category: 'advanced',
    title: 'ESC8 HTTP Enrollment',
    description: 'ADCS web enrollment via HTTP. Enables NTLM relay attacks against certificate enrollment.',
    count: affected.length,
    affectedEntities: includeDetails ? affected.map((ca) => ca.dn) : undefined,
  };
}
