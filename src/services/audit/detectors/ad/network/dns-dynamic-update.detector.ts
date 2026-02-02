/**
 * DNS Dynamic Update Detector
 *
 * Detects insecure DNS dynamic updates.
 * Story 1.7: AD Vulnerability Detection Engine
 * Phase 3: Network Infrastructure
 */

import { Finding } from '../../../../../types/finding.types';
import { DnsZone } from './types';

/**
 * Detect insecure DNS dynamic updates
 *
 * DNS zones allowing non-secure dynamic updates enable DNS poisoning attacks.
 *
 * @param dnsZones - Array of DNS zones (if available)
 * @param _includeDetails - Whether to include affected entity details
 * @returns Finding for DNS_DYNAMIC_UPDATE_INSECURE
 */
export function detectDnsDynamicUpdateInsecure(
  dnsZones: DnsZone[],
  _includeDetails: boolean
): Finding {
  const affected = dnsZones.filter(
    (zone) =>
      zone.dynamicUpdate === 1 || // nonsecure
      zone.dynamicUpdate === 3 // nonsecureAndSecure
  );

  return {
    type: 'DNS_DYNAMIC_UPDATE_INSECURE',
    severity: 'high',
    category: 'network',
    title: 'DNS Dynamic Update Insecure',
    description:
      'DNS zones allowing non-secure dynamic updates. Attackers can inject malicious DNS records without authentication.',
    count: affected.length,
    affectedEntities: affected.map((z) => z.name),
    details: {
      zones: affected.map((z) => ({
        name: z.name,
        dn: z.dn,
        dynamicUpdate: z.dynamicUpdate,
      })),
    },
  };
}
