/**
 * ESC3 Enrollment Agent Detector
 * Check for ESC3 enrollment agent
 */

import { Finding } from '../../../../../../types/finding.types';

export function detectEsc3EnrollmentAgent(templates: any[], includeDetails: boolean): Finding {
  const affected = templates.filter((t) => {
    return t.pKIExtendedKeyUsage?.includes('1.3.6.1.4.1.311.20.2.1');
  });

  return {
    type: 'ESC3_ENROLLMENT_AGENT',
    severity: 'high',
    category: 'advanced',
    title: 'ESC3 Enrollment Agent',
    description: 'ADCS template with enrollment agent EKU. Can request certificates on behalf of other users.',
    count: affected.length,
    affectedEntities: includeDetails ? affected.map((t) => t.dn) : undefined,
  };
}
