/**
 * ESC4 Vulnerable Template ACL Detector
 * Check for ESC4 vulnerable template ACL
 */

import { Finding } from '../../../../../../types/finding.types';

export function detectEsc4VulnerableTemplateAcl(templates: any[], includeDetails: boolean): Finding {
  const affected = templates.filter((t) => {
    return t.hasWeakAcl; // This would be populated by ACL analysis
  });

  return {
    type: 'ESC4_VULNERABLE_TEMPLATE_ACL',
    severity: 'high',
    category: 'advanced',
    title: 'ESC4 Vulnerable Template ACL',
    description: 'Certificate template with weak ACLs. Can modify template to make it vulnerable to ESC1/ESC2.',
    count: affected.length,
    affectedEntities: includeDetails ? affected.map((t) => t.dn) : undefined,
  };
}
