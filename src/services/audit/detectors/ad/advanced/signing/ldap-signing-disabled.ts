/**
 * LDAP Signing Disabled Detector
 * Check if LDAP signing is disabled
 * Requires GPO settings from SYSVOL
 */

import { ADDomain } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';
import { GpoSecuritySettings } from '../types';

export function detectLdapSigningDisabled(
  gpoSettings: GpoSecuritySettings | null,
  domain: ADDomain | null,
  includeDetails: boolean
): Finding {
  // If we have GPO settings, use them
  if (gpoSettings && gpoSettings.ldapServerIntegrity !== undefined) {
    const signingDisabled = gpoSettings.ldapServerIntegrity === 0;

    return {
      type: 'LDAP_SIGNING_DISABLED',
      severity: 'critical',
      category: 'advanced',
      title: 'LDAP Signing Not Required',
      description:
        'LDAP server signing is not required. This allows NTLM relay attacks and man-in-the-middle attacks against LDAP connections.',
      count: signingDisabled ? 1 : 0,
      affectedEntities: includeDetails && signingDisabled && domain ? [domain.dn] : undefined,
      details: signingDisabled
        ? {
            recommendation: 'Configure "Domain controller: LDAP server signing requirements" to "Require signing".',
            currentSetting: gpoSettings.ldapServerIntegrity,
            requiredSetting: 2,
          }
        : undefined,
    };
  }

  // If GPO settings not available, assume vulnerable (Windows defaults don't require LDAP signing)
  return {
    type: 'LDAP_SIGNING_DISABLED',
    severity: 'critical',
    category: 'advanced',
    title: 'LDAP Signing Not Configured in GPO',
    description:
      'LDAP signing is not configured via Group Policy. Windows defaults do not require LDAP signing, making this environment vulnerable to LDAP relay attacks.',
    count: 1,
    affectedEntities: includeDetails && domain ? [domain.dn] : undefined,
    details: {
      recommendation:
        'Configure "Domain controller: LDAP server signing requirements" to "Require signing" via Group Policy.',
      note: 'No GPO security template found. Windows defaults do not require LDAP signing.',
    },
  };
}
