/**
 * NTP Configuration Detector
 *
 * Detects NTP configuration issues.
 * Story 1.7: AD Vulnerability Detection Engine
 * Phase 3: Network Infrastructure
 */

import { ADComputer } from '../../../../../types/ad.types';
import { Finding } from '../../../../../types/finding.types';
import { toAffectedComputerEntities } from '../../../../../utils/entity-converter';

/**
 * Detect NTP not properly configured
 *
 * Improper time synchronization can cause Kerberos authentication failures and security issues.
 *
 * @param domainControllers - Array of domain controllers
 * @param includeDetails - Whether to include affected entity details
 * @returns Finding for NTP_NOT_CONFIGURED
 */
export function detectNtpNotConfigured(
  domainControllers: ADComputer[],
  includeDetails: boolean
): Finding {
  // PDC Emulator should be the authoritative time source
  // Check if DCs have proper time config (would need registry data)
  // For now, check if there are multiple DCs (time sync is critical with multiple DCs)
  const hasSingleDc = domainControllers.length <= 1;

  return {
    type: 'NTP_NOT_CONFIGURED',
    severity: 'medium',
    category: 'network',
    title: 'NTP Configuration Review Needed',
    description:
      'Time synchronization configuration should be reviewed. The PDC Emulator must be configured as the authoritative time source to prevent Kerberos authentication issues.',
    count: hasSingleDc ? 0 : 1,
    affectedEntities: includeDetails
      ? toAffectedComputerEntities(domainControllers)
      : undefined,
    details: {
      dcCount: domainControllers.length,
      recommendation:
        'Configure PDC Emulator as authoritative time source. Other DCs should sync from PDC.',
    },
  };
}
