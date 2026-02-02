/**
 * ESC1 Vulnerable Template Detector
 * Check for ESC1 vulnerable certificate template
 */

import { Finding } from '../../../../../../types/finding.types';

export function detectEsc1VulnerableTemplate(templates: any[], includeDetails: boolean): Finding {
  const affected = templates.filter((t) => {
    const hasClientAuth = t.pKIExtendedKeyUsage?.includes('1.3.6.1.5.5.7.3.2');
    const enrolleeSuppliesSubject = t['msPKI-Certificate-Name-Flag'] && (t['msPKI-Certificate-Name-Flag'] & 0x1) !== 0;
    return hasClientAuth && enrolleeSuppliesSubject;
  });

  return {
    type: 'ESC1_VULNERABLE_TEMPLATE',
    severity: 'high',
    category: 'advanced',
    title: 'ESC1 Vulnerable Template',
    description: 'ADCS template with client auth + enrollee supplies subject. Enables domain compromise by obtaining cert for any user.',
    count: affected.length,
    affectedEntities: includeDetails ? affected.map((t) => t.dn) : undefined,
  };
}
