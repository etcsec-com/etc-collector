/**
 * Weak Kerberos Policy Detector
 * Check for weak Kerberos policy
 */

import { ADDomain } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';

export function detectWeakKerberosPolicy(domain: ADDomain | null, includeDetails: boolean): Finding {
  if (!domain) {
    return {
      type: 'WEAK_KERBEROS_POLICY',
      severity: 'medium',
      category: 'advanced',
      title: 'Weak Kerberos Policy',
      description: 'Unable to check Kerberos policy.',
      count: 0,
    };
  }

  const maxTicketAge = (domain as any).maxTicketAge || 0;
  const maxRenewAge = (domain as any).maxRenewAge || 0;

  const isWeak = maxTicketAge > 10 || maxRenewAge > 7;

  return {
    type: 'WEAK_KERBEROS_POLICY',
    severity: 'medium',
    category: 'advanced',
    title: 'Weak Kerberos Policy',
    description: 'Kerberos ticket lifetimes exceed recommended values. Longer window for ticket-based attacks.',
    count: isWeak ? 1 : 0,
    affectedEntities: includeDetails && isWeak ? [domain.dn] : undefined,
    details: isWeak
      ? {
          maxTicketAge,
          maxRenewAge,
        }
      : undefined,
  };
}
