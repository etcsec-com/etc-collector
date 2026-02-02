/**
 * NTLM Relay Opportunity Detector
 * Check for NTLM relay opportunity
 */

import { ADDomain } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';

export function detectNtlmRelayOpportunity(domain: ADDomain | null, includeDetails: boolean): Finding {
  if (!domain) {
    return {
      type: 'NTLM_RELAY_OPPORTUNITY',
      severity: 'medium',
      category: 'advanced',
      title: 'NTLM Relay Opportunity',
      description: 'Unable to check LDAP signing configuration.',
      count: 0,
    };
  }

  const ldapSigningRequired = (domain as any).ldapSigningRequired;
  const channelBindingRequired = (domain as any).channelBindingRequired;

  const isVulnerable = !ldapSigningRequired || !channelBindingRequired;

  return {
    type: 'NTLM_RELAY_OPPORTUNITY',
    severity: 'medium',
    category: 'advanced',
    title: 'NTLM Relay Opportunity',
    description: 'LDAP signing or channel binding not enforced. Enables NTLM relay attacks.',
    count: isVulnerable ? 1 : 0,
    affectedEntities: includeDetails && isVulnerable ? [domain.dn] : undefined,
  };
}
