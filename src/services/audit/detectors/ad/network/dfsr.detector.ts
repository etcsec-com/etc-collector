/**
 * DFSR Configuration Detector
 *
 * Detects when DFSR is not configured (legacy FRS in use).
 * Story 1.7: AD Vulnerability Detection Engine
 * Phase 3: Network Infrastructure
 */

import { ADDomain } from '../../../../../types/ad.types';
import { Finding } from '../../../../../types/finding.types';

/**
 * Helper function to get domain functional level name
 */
export function getDomainLevelName(level: number): string {
  const levels: Record<number, string> = {
    0: 'Windows 2000',
    1: 'Windows Server 2003 Interim',
    2: 'Windows Server 2003',
    3: 'Windows Server 2008',
    4: 'Windows Server 2008 R2',
    5: 'Windows Server 2012',
    6: 'Windows Server 2012 R2',
    7: 'Windows Server 2016',
  };
  return levels[level] || `Unknown (${level})`;
}

/**
 * Detect DFSR not configured (legacy FRS in use)
 *
 * FRS is deprecated and should be migrated to DFSR.
 *
 * @param domain - Domain information
 * @param _includeDetails - Whether to include affected entity details
 * @returns Finding for DFSR_NOT_CONFIGURED
 */
export function detectDfsrNotConfigured(
  domain: ADDomain | null,
  _includeDetails: boolean
): Finding {
  // Check domain functional level - DFSR requires 2008+ functional level
  const domainLevel = domain?.domainFunctionalLevel ?? 0;
  // Levels: 0=2000, 2=2003, 3=2008, 4=2008R2, 5=2012, 6=2012R2, 7=2016

  // If level is 2003 or lower, might still be using FRS
  const potentialFrsUse = domainLevel <= 2;

  return {
    type: 'DFSR_NOT_CONFIGURED',
    severity: potentialFrsUse ? 'medium' : 'low',
    category: 'network',
    title: 'DFSR Migration Status',
    description:
      'FRS (File Replication Service) is deprecated. SYSVOL should be replicated using DFSR (DFS Replication) for better reliability.',
    count: potentialFrsUse ? 1 : 0,
    details: {
      domainFunctionalLevel: domainLevel,
      domainFunctionalLevelName: getDomainLevelName(domainLevel),
      potentialFrsUse,
      recommendation: potentialFrsUse
        ? 'Migrate SYSVOL replication from FRS to DFSR using dfsrmig.exe'
        : 'Verify DFSR health with dcdiag /e /test:dfsrevent',
    },
  };
}
