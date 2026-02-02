/**
 * Foreign Security Principals Detector
 * Check for foreign security principals
 */

import { Finding } from '../../../../../../types/finding.types';

export function detectForeignSecurityPrincipals(fsps: any[], includeDetails: boolean): Finding {
  return {
    type: 'FOREIGN_SECURITY_PRINCIPALS',
    severity: 'medium',
    category: 'advanced',
    title: 'Foreign Security Principals',
    description: 'Foreign security principals from external forests. Potential for cross-forest privilege escalation.',
    count: fsps.length,
    affectedEntities: includeDetails ? fsps.map((fsp) => fsp.dn) : undefined,
  };
}
