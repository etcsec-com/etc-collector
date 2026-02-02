/**
 * SMBv1 Enabled Detector
 * Check if SMBv1 is enabled
 * Requires GPO settings from SYSVOL
 */

import { ADDomain } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';
import { GpoSecuritySettings } from '../types';

export function detectSmbV1Enabled(
  gpoSettings: GpoSecuritySettings | null,
  domain: ADDomain | null,
  includeDetails: boolean
): Finding {
  if (gpoSettings && (gpoSettings.smbv1ServerEnabled !== undefined || gpoSettings.smbv1ClientEnabled !== undefined)) {
    const smbv1Enabled = gpoSettings.smbv1ServerEnabled === true || gpoSettings.smbv1ClientEnabled === true;

    return {
      type: 'SMB_V1_ENABLED',
      severity: 'high',
      category: 'advanced',
      title: 'SMBv1 Protocol Enabled',
      description:
        'SMBv1 protocol is enabled. SMBv1 is deprecated and vulnerable to attacks like EternalBlue (WannaCry, NotPetya).',
      count: smbv1Enabled ? 1 : 0,
      affectedEntities: includeDetails && smbv1Enabled && domain ? [domain.dn] : undefined,
      details: smbv1Enabled
        ? {
            recommendation: 'Disable SMBv1 on all systems. Use SMBv2/v3 instead.',
            smbv1Server: gpoSettings.smbv1ServerEnabled,
            smbv1Client: gpoSettings.smbv1ClientEnabled,
          }
        : undefined,
    };
  }

  return {
    type: 'SMB_V1_ENABLED',
    severity: 'high',
    category: 'advanced',
    title: 'SMBv1 Configuration Unknown',
    description: 'Unable to determine SMBv1 configuration. Manual review recommended.',
    count: 0,
    details: {
      note: 'GPO/Registry settings not available. Check SMB1 registry values and Windows features manually.',
    },
  };
}
