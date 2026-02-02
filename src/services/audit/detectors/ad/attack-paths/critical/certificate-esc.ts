/**
 * Certificate Template Escalation Detector
 *
 * Detects ADCS certificate template paths to Domain Admin.
 * Vulnerable ESC templates that enable DA compromise.
 */

import { ADUser, ADGroup, ADComputer } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';

/**
 * Detect ADCS certificate template paths to Domain Admin
 * Vulnerable ESC templates that enable DA compromise
 */
export function detectPathCertificateEsc(
  templates: any[],
  users: ADUser[],
  _groups: ADGroup[],
  _computers: ADComputer[],
  includeDetails: boolean
): Finding {
  // Note: groups and computers could be used for more complex enrollment permission checks

  // Find ESC1-like templates (client auth + enrollee supplies subject)
  const vulnerableTemplates = templates.filter((t) => {
    const hasClientAuth = t.pKIExtendedKeyUsage?.includes('1.3.6.1.5.5.7.3.2');
    const enrolleeSupplies = t['msPKI-Certificate-Name-Flag'] && (t['msPKI-Certificate-Name-Flag'] & 0x1) !== 0;
    return hasClientAuth && enrolleeSupplies;
  });

  if (vulnerableTemplates.length === 0) {
    return {
      type: 'PATH_CERTIFICATE_ESC',
      severity: 'critical',
      category: 'attack-paths',
      title: 'Certificate Template Escalation to Domain Admin',
      description: 'No vulnerable certificate templates that enable privilege escalation to Domain Admin.',
      count: 0,
    };
  }

  // Find non-admin users who can enroll
  // This is simplified - full check would require CA enrollment permissions
  const usersWhoCanEnroll = users.filter((u) => u.enabled && u.adminCount !== 1);

  return {
    type: 'PATH_CERTIFICATE_ESC',
    severity: 'critical',
    category: 'attack-paths',
    title: 'Certificate Template Escalation to Domain Admin',
    description:
      'Vulnerable certificate templates (ESC1-like) allow users to request certificates for any user including Domain Admins.',
    count: vulnerableTemplates.length,
    affectedEntities: includeDetails ? vulnerableTemplates.map((t) => t.dn || t.cn) : undefined,
    details: {
      vulnerableTemplates: vulnerableTemplates.map((t) => t.cn || t.name),
      attackVector: 'Enroll in vulnerable template → Request cert as DA → Authenticate as DA',
      potentialAttackers: usersWhoCanEnroll.length,
      mitigation:
        'Disable ENROLLEE_SUPPLIES_SUBJECT flag, restrict enrollment permissions, use Certificate Manager Approval',
    },
  };
}
