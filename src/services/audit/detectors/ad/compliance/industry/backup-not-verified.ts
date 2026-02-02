/**
 * BACKUP_AD_NOT_VERIFIED - No recent AD backup
 * Frameworks: SOC2 A1.2, DORA Art.11, ISO27001 A.12.3.1
 * Checks if AD has recent backup (based on tombstone lifetime and domain metadata)
 */

import { ADDomain } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';

export function detectBackupNotVerified(
  domain: ADDomain,
  _includeDetails: boolean
): Finding {
  const issues: string[] = [];

  // Check tombstone lifetime (default 180 days, should be configured)
  const tombstoneLifetime = (domain['tombstoneLifetime'] as number) || 180;

  // If tombstone is default, backup policy may not be reviewed
  if (tombstoneLifetime === 180 || tombstoneLifetime === 60) {
    issues.push(`Tombstone lifetime is default (${tombstoneLifetime} days) - backup policy may not be configured`);
  }

  // Check for backup indicators in domain (this is heuristic)
  // Real backup verification requires checking Windows Server Backup or third-party tools
  const lastBackup = domain['lastBackupTime'] as Date | undefined;
  if (!lastBackup) {
    issues.push('No backup metadata found - verify AD backup is configured and tested');
  }

  return {
    type: 'BACKUP_AD_NOT_VERIFIED',
    severity: 'high',
    category: 'compliance',
    title: 'AD Backup Not Verified',
    description:
      'Active Directory backup configuration cannot be verified. Required by SOC2 A1.2, DORA Article 11, ISO27001 A.12.3.1.',
    count: issues.length > 0 ? 1 : 0,
    details: issues.length > 0 ? {
      violations: issues,
      frameworks: ['SOC2', 'DORA', 'ISO27001'],
      controls: ['A1.2', 'Art.11', 'A.12.3.1'],
      recommendation: 'Configure and regularly test AD system state backups',
    } : undefined,
  };
}
