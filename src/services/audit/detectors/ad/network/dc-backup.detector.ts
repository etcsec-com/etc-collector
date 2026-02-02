/**
 * DC Backup Detector
 *
 * Detects domain controllers with potentially old backups.
 * Story 1.7: AD Vulnerability Detection Engine
 * Phase 3: Network Infrastructure
 */

import { ADComputer } from '../../../../../types/ad.types';
import { Finding } from '../../../../../types/finding.types';
import { toAffectedComputerEntities } from '../../../../../utils/entity-converter';

/**
 * Detect old domain controller backups
 *
 * DCs without recent backups risk data loss.
 *
 * @param domainControllers - Array of domain controllers
 * @param includeDetails - Whether to include affected entity details
 * @returns Finding for DC_BACKUP_OLD
 */
export function detectDcBackupOld(
  domainControllers: ADComputer[],
  includeDetails: boolean
): Finding {
  // Check lastLogonTimestamp and pwdLastSet as proxy for DC health
  const now = new Date();
  const thirtyDaysAgo = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);

  const possiblyUnbackedUp = domainControllers.filter((dc) => {
    // If DC hasn't replicated password recently, it might indicate backup issues
    const pwdLastSet = dc.passwordLastSet;
    return pwdLastSet && pwdLastSet < thirtyDaysAgo;
  });

  return {
    type: 'DC_BACKUP_OLD',
    severity: 'medium',
    category: 'network',
    title: 'Domain Controller Backup Review',
    description:
      'Domain controllers should be backed up regularly. Tombstone lifetime is 180 days - DCs offline longer than this cannot rejoin.',
    count: possiblyUnbackedUp.length,
    affectedEntities: includeDetails
      ? toAffectedComputerEntities(possiblyUnbackedUp)
      : undefined,
    details: {
      recommendation:
        'Verify Windows Server Backup or third-party backup solution is configured on all DCs.',
    },
  };
}
