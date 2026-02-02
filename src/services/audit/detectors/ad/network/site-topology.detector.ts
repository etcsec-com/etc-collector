/**
 * Site Topology Detector
 *
 * Detects AD site topology issues.
 * Story 1.7: AD Vulnerability Detection Engine
 * Phase 3: Network Infrastructure
 */

import { Finding } from '../../../../../types/finding.types';
import { ADSite } from './types';

/**
 * Detect site topology issues
 *
 * Sites without subnets or DCs can cause authentication performance issues.
 *
 * @param sites - Array of AD sites
 * @param _includeDetails - Whether to include affected entity details
 * @returns Finding for SITE_TOPOLOGY_ISSUES
 */
export function detectSiteTopologyIssues(
  sites: ADSite[],
  _includeDetails: boolean
): Finding {
  // Sites without servers (DCs) are problematic
  const sitesWithoutDc = sites.filter(
    (site) => !site.servers || site.servers.length === 0
  );

  return {
    type: 'SITE_TOPOLOGY_ISSUES',
    severity: 'medium',
    category: 'network',
    title: 'AD Site Topology Issues',
    description:
      'Sites without domain controllers cause clients to authenticate against remote DCs, increasing latency and WAN traffic.',
    count: sitesWithoutDc.length,
    affectedEntities: sitesWithoutDc.map((s) => s.name),
    details: {
      sitesWithoutDc: sitesWithoutDc.map((s) => s.name),
    },
  };
}
