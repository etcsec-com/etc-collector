/**
 * Computer SMB Signing Disabled Detector
 * Check for computer with SMB signing disabled
 */

import { ADComputer } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';
import { toAffectedComputerEntities } from '../../../../../../utils/entity-converter';

export function detectComputerSmbSigningDisabled(computers: ADComputer[], includeDetails: boolean): Finding {
  // Note: This would typically require querying computer configuration
  // For now, we check for an attribute that would be set if SMB signing is disabled
  const affected = computers.filter((c) => {
    return 'smbSigningDisabled' in c && (c as any).smbSigningDisabled;
  });

  return {
    type: 'COMPUTER_SMB_SIGNING_DISABLED',
    severity: 'low',
    category: 'computers',
    title: 'Computer SMB Signing Disabled',
    description: 'Computer with SMB signing disabled. Vulnerable to SMB relay attacks (informational finding).',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedComputerEntities(affected) : undefined,
  };
}
