/**
 * DC Time Sync Detector
 *
 * Detects domain controller time synchronization issues.
 * Story 1.7: AD Vulnerability Detection Engine
 * Phase 3: Network Infrastructure
 */

import { ADComputer } from '../../../../../types/ad.types';
import { Finding } from '../../../../../types/finding.types';
import { toAffectedComputerEntities } from '../../../../../utils/entity-converter';

/**
 * Detect domain controller time sync issues
 *
 * Time synchronization issues cause Kerberos failures.
 *
 * @param domainControllers - Array of domain controllers
 * @param includeDetails - Whether to include affected entity details
 * @returns Finding for DC_TIME_SYNC_ISSUE
 */
export function detectDcTimeSyncIssue(
  domainControllers: ADComputer[],
  includeDetails: boolean
): Finding {
  // Check if any DC has very old lastLogon (might indicate it's offline/out of sync)
  const now = new Date();
  const sevenDaysAgo = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);

  const possibleTimeSyncIssues = domainControllers.filter((dc) => {
    const lastLogon = dc.lastLogon;
    return lastLogon && lastLogon < sevenDaysAgo;
  });

  return {
    type: 'DC_TIME_SYNC_ISSUE',
    severity: 'high',
    category: 'network',
    title: 'DC Time Synchronization Review',
    description:
      'Domain controllers with potential time sync issues detected. Kerberos requires time difference < 5 minutes.',
    count: possibleTimeSyncIssues.length,
    affectedEntities: includeDetails
      ? toAffectedComputerEntities(possibleTimeSyncIssues)
      : undefined,
    details: {
      possibleIssues: possibleTimeSyncIssues.map((dc) => dc.sAMAccountName),
      recommendation:
        'Run "w32tm /query /status" on each DC to verify time configuration.',
    },
  };
}
