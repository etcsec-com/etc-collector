/**
 * Machine Account Quota Abuse Detector
 * Check for machine account quota abuse
 */

import { ADDomain } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';

export function detectMachineAccountQuotaAbuse(domain: ADDomain | null, includeDetails: boolean): Finding {
  if (!domain) {
    return {
      type: 'MACHINE_ACCOUNT_QUOTA_ABUSE',
      severity: 'medium',
      category: 'advanced',
      title: 'Machine Account Quota Abuse',
      description: 'Unable to check machine account quota.',
      count: 0,
    };
  }

  const quota = (domain as any)['ms-DS-MachineAccountQuota'];
  const isVulnerable = typeof quota === 'number' && quota > 0;

  return {
    type: 'MACHINE_ACCOUNT_QUOTA_ABUSE',
    severity: 'medium',
    category: 'advanced',
    title: 'Machine Account Quota Abuse',
    description: 'ms-DS-MachineAccountQuota > 0. Non-admin users can join computers to domain (potential Kerberos attacks).',
    count: isVulnerable ? 1 : 0,
    affectedEntities: includeDetails && isVulnerable ? [domain.dn] : undefined,
    details: isVulnerable
      ? {
          quota,
        }
      : undefined,
  };
}
