/**
 * Security Log Size Detector
 *
 * Detects if security log size is too small.
 * Small logs mean events are overwritten quickly, losing forensic data.
 */

import { ADDomain } from '../../../../../types/ad.types';
import { Finding } from '../../../../../types/finding.types';
import { MonitoringGpoSettings } from './types';

/**
 * Detect if security log size is too small
 * Small logs mean events are overwritten quickly, losing forensic data
 */
export function detectSecurityLogSizeSmall(
  gpoSettings: MonitoringGpoSettings | null,
  domain: ADDomain | null,
  includeDetails: boolean
): Finding {
  const MINIMUM_LOG_SIZE_KB = 128 * 1024; // 128 MB minimum recommended

  if (gpoSettings?.eventLogSettings?.securityLogMaxSize !== undefined) {
    const logSize = gpoSettings.eventLogSettings.securityLogMaxSize;
    const isTooSmall = logSize < MINIMUM_LOG_SIZE_KB;

    return {
      type: 'SECURITY_LOG_SIZE_SMALL',
      severity: 'medium',
      category: 'monitoring',
      title: 'Security Log Size Insufficient',
      description: `Security event log maximum size is ${Math.round(logSize / 1024)} MB. Small logs cause events to be overwritten quickly, losing forensic data.`,
      count: isTooSmall ? 1 : 0,
      affectedEntities: includeDetails && isTooSmall && domain ? [domain.dn] : undefined,
      details: isTooSmall
        ? {
            currentSizeKB: logSize,
            currentSizeMB: Math.round(logSize / 1024),
            recommendedSizeKB: MINIMUM_LOG_SIZE_KB,
            recommendedSizeMB: Math.round(MINIMUM_LOG_SIZE_KB / 1024),
            recommendation: 'Increase Security log maximum size to at least 128 MB via GPO.',
            risks: [
              'Critical events may be lost due to log rotation',
              'Incident response hampered by missing events',
              'Compliance violations for log retention requirements',
            ],
          }
        : undefined,
    };
  }

  // Return informational finding if we can't determine log size
  // Don't count as a vulnerability since we can't verify
  return {
    type: 'SECURITY_LOG_SIZE_SMALL',
    severity: 'medium',
    category: 'monitoring',
    title: 'Security Log Size Configuration Unknown',
    description: 'Unable to determine security event log size configuration.',
    count: 0,
    details: {
      note: 'GPO event log settings not available. Verify Security log maximum size manually.',
      recommendedSizeMB: Math.round(MINIMUM_LOG_SIZE_KB / 1024),
    },
  };
}
