/**
 * LDAP Channel Binding Disabled Detector
 * Check if LDAP channel binding is disabled
 * Requires GPO settings from SYSVOL
 */

import { ADDomain } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';
import { GpoSecuritySettings } from '../types';

export function detectLdapChannelBindingDisabled(
  gpoSettings: GpoSecuritySettings | null,
  domain: ADDomain | null,
  includeDetails: boolean
): Finding {
  if (gpoSettings && gpoSettings.ldapChannelBinding !== undefined) {
    const bindingDisabled = gpoSettings.ldapChannelBinding === 0;

    return {
      type: 'LDAP_CHANNEL_BINDING_DISABLED',
      severity: 'high',
      category: 'advanced',
      title: 'LDAP Channel Binding Not Required',
      description:
        'LDAP channel binding is not required. This allows NTLM relay attacks against LDAPS connections even when signing is enabled.',
      count: bindingDisabled ? 1 : 0,
      affectedEntities: includeDetails && bindingDisabled && domain ? [domain.dn] : undefined,
      details: bindingDisabled
        ? {
            recommendation: 'Configure "Domain controller: LDAP server channel binding token requirements" to "Always".',
            currentSetting: gpoSettings.ldapChannelBinding,
            requiredSetting: 2,
          }
        : undefined,
    };
  }

  return {
    type: 'LDAP_CHANNEL_BINDING_DISABLED',
    severity: 'high',
    category: 'advanced',
    title: 'LDAP Channel Binding Configuration Unknown',
    description: 'Unable to determine LDAP channel binding configuration. Manual review recommended.',
    count: 0,
    details: {
      note: 'GPO/Registry settings not available. Check LdapEnforceChannelBinding registry value manually.',
    },
  };
}
