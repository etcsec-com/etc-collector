/**
 * ADCS Weak Permissions Detector
 * Check for ADCS weak permissions
 */

import { Finding } from '../../../../../../types/finding.types';

export function detectAdcsWeakPermissions(templates: any[], includeDetails: boolean): Finding {
  const affected = templates.filter((t) => {
    // Check if template has weak ACLs allowing enrollment by non-admins
    return t.hasWeakEnrollmentAcl || t.hasGenericAllPermission;
  });

  return {
    type: 'ADCS_WEAK_PERMISSIONS',
    severity: 'medium',
    category: 'advanced',
    title: 'ADCS Weak Permissions',
    description: 'Weak permissions on ADCS objects or certificate templates allow unauthorized enrollment.',
    count: affected.length,
    affectedEntities: includeDetails ? affected.map((t) => t.dn || t.name) : undefined,
  };
}
