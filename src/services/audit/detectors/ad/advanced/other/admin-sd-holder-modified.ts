/**
 * AdminSDHolder Modified Detector
 * Detect modified AdminSDHolder permissions
 *
 * AdminSDHolder template is applied to protected accounts every 60 minutes.
 * Modified permissions on AdminSDHolder will propagate to all protected accounts.
 */

import { ADDomain } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';

export function detectAdminSdHolderModified(
  domain: ADDomain | null,
  _includeDetails: boolean
): Finding {
  // This would require reading the nTSecurityDescriptor of AdminSDHolder
  // For now, check if domain has indicators of modification
  // A proper check would compare against known-good template
  const adminSdHolderInfo = domain
    ? (domain as Record<string, unknown>)['adminSDHolderModified'] as boolean | undefined
    : undefined;

  return {
    type: 'ADMIN_SD_HOLDER_MODIFIED',
    severity: 'high',
    category: 'advanced',
    title: 'AdminSDHolder Review Required',
    description:
      'AdminSDHolder permissions should be reviewed. Modifications propagate to all protected accounts ' +
      '(Domain Admins, Enterprise Admins, etc.) via SDProp process.',
    count: adminSdHolderInfo ? 1 : 0,
    details: {
      recommendation:
        'Compare AdminSDHolder ACL against baseline. Look for non-standard principals with permissions.',
      checkCommand: 'Get-ADObject "CN=AdminSDHolder,CN=System,DC=..." -Properties nTSecurityDescriptor',
    },
  };
}
