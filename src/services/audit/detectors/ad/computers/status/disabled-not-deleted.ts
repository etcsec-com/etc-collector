/**
 * Computer Disabled Not Deleted Detector
 * Check for disabled computers not deleted (>30 days)
 */

import { ADComputer } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';
import { toAffectedComputerEntities } from '../../../../../../utils/entity-converter';
import { toTimestamp } from '../utils';

export function detectComputerDisabledNotDeleted(computers: ADComputer[], includeDetails: boolean): Finding {
  const now = Date.now();
  const thirtyDaysAgo = now - 30 * 24 * 60 * 60 * 1000;

  // Debug stats
  const debugStats: {
    total: number;
    enabled: number;
    noWhenChanged: number;
    recent: number;
    old: number;
    sampleDates: {
      name: string;
      raw: unknown;
      rawType: string;
      rawStringified: string;
      parsed: number | null;
      asIso: string | null;
      whenCreated: unknown;
    }[];
  } = { total: 0, enabled: 0, noWhenChanged: 0, recent: 0, old: 0, sampleDates: [] };

  const affected = computers.filter((c) => {
    debugStats.total++;
    if (c.enabled) {
      debugStats.enabled++;
      return false;
    }

    // Use toTimestamp for robust date handling
    const rawWhenChanged = (c as any).whenChanged;
    const whenChangedTime = toTimestamp(rawWhenChanged);

    // Capture sample dates for debugging (first 5 disabled computers)
    if (debugStats.sampleDates.length < 5) {
      debugStats.sampleDates.push({
        name: c.sAMAccountName || 'unknown',
        raw: rawWhenChanged,
        rawType: typeof rawWhenChanged,
        rawStringified: JSON.stringify(rawWhenChanged),
        parsed: whenChangedTime,
        asIso: whenChangedTime ? new Date(whenChangedTime).toISOString() : null,
        whenCreated: (c as any).whenCreated, // Also capture whenCreated for comparison
      });
    }

    if (!whenChangedTime) {
      debugStats.noWhenChanged++;
      return false;
    }

    if (whenChangedTime < thirtyDaysAgo) {
      debugStats.old++;
      return true;
    }
    debugStats.recent++;
    return false;
  });

  return {
    type: 'COMPUTER_DISABLED_NOT_DELETED',
    severity: 'medium',
    category: 'computers',
    title: 'Computer Disabled Not Deleted',
    description: 'Disabled computer not deleted (>30 days). Clutters AD, potential security oversight.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedComputerEntities(affected) : undefined,
    details: {
      debug: debugStats,
      threshold: '30 days',
      checkDate: new Date(thirtyDaysAgo).toISOString(),
      nowDate: new Date(now).toISOString(),
    },
  };
}
