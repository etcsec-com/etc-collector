/**
 * Subnet Missing Detector
 *
 * Detects AD sites missing subnet definitions.
 * Story 1.7: AD Vulnerability Detection Engine
 * Phase 3: Network Infrastructure
 */

import { Finding } from '../../../../../types/finding.types';
import { ADSite, ADSubnet } from './types';

/**
 * Detect missing subnets
 *
 * Subnets without site assignments cause suboptimal DC selection.
 *
 * @param sites - Array of AD sites
 * @param subnets - Array of AD subnets
 * @param _includeDetails - Whether to include affected entity details
 * @returns Finding for SUBNET_MISSING
 */
export function detectSubnetMissing(
  sites: ADSite[],
  subnets: ADSubnet[],
  _includeDetails: boolean
): Finding {
  // Check for sites without subnets
  const sitesWithoutSubnets = sites.filter((site) => {
    const siteSubnets = subnets.filter((sub) => sub.site === site.dn);
    return siteSubnets.length === 0;
  });

  return {
    type: 'SUBNET_MISSING',
    severity: 'low',
    category: 'network',
    title: 'AD Sites Missing Subnets',
    description:
      'Sites without subnet definitions. Clients in undefined subnets will select DCs randomly, potentially crossing WAN links.',
    count: sitesWithoutSubnets.length,
    affectedEntities: sitesWithoutSubnets.map((s) => s.name),
    details: {
      totalSites: sites.length,
      totalSubnets: subnets.length,
      sitesWithoutSubnets: sitesWithoutSubnets.map((s) => s.name),
    },
  };
}
