/**
 * Machine Account Quota High Detector
 * Check for machine account quota set higher than default
 * Default is 10 - values > 10 indicate intentional increase
 */

import { ADDomain } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';

export function detectMachineAccountQuotaHigh(domain: ADDomain | null, includeDetails: boolean): Finding {
  if (!domain) {
    return {
      type: 'MACHINE_ACCOUNT_QUOTA_HIGH',
      severity: 'high',
      category: 'advanced',
      title: 'Machine Account Quota Elevated',
      description: 'Unable to check machine account quota.',
      count: 0,
    };
  }

  const quota = (domain as any)['ms-DS-MachineAccountQuota'];
  const DEFAULT_QUOTA = 10;
  const isElevated = typeof quota === 'number' && quota > DEFAULT_QUOTA;

  return {
    type: 'MACHINE_ACCOUNT_QUOTA_HIGH',
    severity: 'high',
    category: 'advanced',
    title: 'Machine Account Quota Elevated Above Default',
    description:
      'ms-DS-MachineAccountQuota is higher than the default (10). Someone intentionally increased this value, allowing non-admin users to join more computers to the domain.',
    count: isElevated ? 1 : 0,
    affectedEntities: includeDetails && isElevated ? [domain.dn] : undefined,
    details: isElevated
      ? {
          currentQuota: quota,
          defaultQuota: DEFAULT_QUOTA,
          recommendation: 'Set ms-DS-MachineAccountQuota to 0 to prevent non-admin domain joins.',
        }
      : undefined,
  };
}
