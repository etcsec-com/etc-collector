/**
 * Anonymous LDAP Access Detector
 * Check if anonymous LDAP access is allowed
 * This is tested during the audit via separate anonymous bind attempt
 */

import { ADDomain } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';

export function detectAnonymousLdapAccess(
  anonymousAccessAllowed: boolean,
  domain: ADDomain | null,
  includeDetails: boolean
): Finding {
  return {
    type: 'ANONYMOUS_LDAP_ACCESS',
    severity: 'medium',
    category: 'advanced',
    title: 'Anonymous LDAP Access Allowed',
    description:
      'LDAP server accepts anonymous binds. Attackers can enumerate AD objects (users, groups, computers) without valid credentials.',
    count: anonymousAccessAllowed ? 1 : 0,
    affectedEntities: includeDetails && anonymousAccessAllowed && domain ? [domain.dn] : undefined,
    details: anonymousAccessAllowed
      ? {
          recommendation:
            'Configure "Network security: LDAP client signing requirements" and restrict anonymous access via dsHeuristics.',
          currentStatus: 'Anonymous bind allowed',
        }
      : undefined,
  };
}
