/**
 * Recycle Bin Disabled Detector
 * Check if AD Recycle Bin is disabled
 * Recycle Bin allows recovery of deleted objects
 */

import { ADDomain } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';

export function detectRecycleBinDisabled(domain: ADDomain | null, includeDetails: boolean): Finding {
  if (!domain) {
    return {
      type: 'RECYCLE_BIN_DISABLED',
      severity: 'medium',
      category: 'advanced',
      title: 'AD Recycle Bin Status Unknown',
      description: 'Unable to determine AD Recycle Bin status.',
      count: 0,
    };
  }

  const recycleBinEnabled = (domain as any).recycleBinEnabled === true;

  return {
    type: 'RECYCLE_BIN_DISABLED',
    severity: 'medium',
    category: 'advanced',
    title: 'AD Recycle Bin Not Enabled',
    description:
      'Active Directory Recycle Bin is not enabled. Deleted objects cannot be easily recovered, which complicates incident response and may lead to permanent data loss.',
    count: recycleBinEnabled ? 0 : 1,
    affectedEntities: includeDetails && !recycleBinEnabled ? [domain.dn] : undefined,
    details: !recycleBinEnabled
      ? {
          recommendation:
            'Enable AD Recycle Bin feature. Note: This requires forest functional level 2008 R2 or higher and is irreversible.',
          currentStatus: 'Disabled',
        }
      : undefined,
  };
}
