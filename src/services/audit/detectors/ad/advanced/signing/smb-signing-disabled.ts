/**
 * SMB Signing Disabled Detector
 * Check if SMB signing is disabled
 * Requires GPO settings from SYSVOL
 *
 * SMB signing prevents man-in-the-middle attacks and NTLM relay attacks.
 * Registry key: MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\RequireSecuritySignature
 */

import { ADDomain } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';
import { GpoSecuritySettings } from '../types';

export function detectSmbSigningDisabled(
  gpoSettings: GpoSecuritySettings | null,
  domain: ADDomain | null,
  includeDetails: boolean
): Finding {
  if (gpoSettings && gpoSettings.smbSigningRequired !== undefined) {
    const signingDisabled = gpoSettings.smbSigningRequired === false;

    return {
      type: 'SMB_SIGNING_DISABLED',
      severity: 'critical',
      category: 'advanced',
      title: 'SMB Signing Not Required',
      description:
        'SMB server signing is not required. This allows man-in-the-middle attacks and NTLM relay attacks against SMB connections.',
      count: signingDisabled ? 1 : 0,
      affectedEntities: includeDetails && signingDisabled && domain ? [domain.dn] : undefined,
      details: signingDisabled
        ? {
            recommendation: 'Configure "Microsoft network server: Digitally sign communications (always)" to Enabled.',
            currentSetting: 'Not Required',
            requiredSetting: 'Required',
            smbServerSigning: gpoSettings.smbSigningRequired,
            smbClientSigning: gpoSettings.smbClientSigningRequired,
          }
        : undefined,
    };
  }

  // If GPO settings not available, assume vulnerable (Windows defaults don't require signing)
  return {
    type: 'SMB_SIGNING_DISABLED',
    severity: 'critical',
    category: 'advanced',
    title: 'SMB Signing Not Configured in GPO',
    description:
      'SMB signing is not configured via Group Policy. Windows defaults do not require SMB signing, making this environment vulnerable to NTLM relay attacks.',
    count: 1,
    affectedEntities: includeDetails && domain ? [domain.dn] : undefined,
    details: {
      recommendation:
        'Configure "Microsoft network server: Digitally sign communications (always)" via Group Policy.',
      note: 'No GPO security template found. Windows defaults do not require SMB signing.',
    },
  };
}
