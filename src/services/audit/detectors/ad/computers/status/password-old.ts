/**
 * Computer Password Old Detector
 * Check for computer with old password (>90 days)
 */

import { ADComputer } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';
import { toAffectedComputerEntities } from '../../../../../../utils/entity-converter';
import { toTimestamp } from '../utils';

export function detectComputerPasswordOld(computers: ADComputer[], includeDetails: boolean): Finding {
  const now = Date.now();
  const ninetyDaysAgo = now - 90 * 24 * 60 * 60 * 1000;

  // Debug: track why computers are filtered out
  let debugStats = { total: 0, disabled: 0, noPwdLastSet: 0, recent: 0, old: 0 };

  const affected = computers.filter((c) => {
    debugStats.total++;
    // Only check enabled computers
    if (!c.enabled) {
      debugStats.disabled++;
      return false;
    }

    // Try pwdLastSet first, then passwordLastSet
    const pwdLastSet = toTimestamp((c as any).pwdLastSet) ?? toTimestamp((c as any).passwordLastSet);
    if (!pwdLastSet) {
      debugStats.noPwdLastSet++;
      return false;
    }

    if (pwdLastSet < ninetyDaysAgo) {
      debugStats.old++;
      return true;
    }
    debugStats.recent++;
    return false;
  });

  return {
    type: 'COMPUTER_PASSWORD_OLD',
    severity: 'high',
    category: 'computers',
    title: 'Computer Password Old',
    description: 'Computer password not changed for 90+ days. Increases risk of password-based attacks.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedComputerEntities(affected) : undefined,
    details: {
      debug: debugStats,
      threshold: '90 days',
      checkDate: new Date(ninetyDaysAgo).toISOString(),
    },
  };
}
