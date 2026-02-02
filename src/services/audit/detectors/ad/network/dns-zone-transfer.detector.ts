/**
 * DNS Zone Transfer Detector
 *
 * Detects unrestricted DNS zone transfers.
 * Story 1.7: AD Vulnerability Detection Engine
 * Phase 3: Network Infrastructure
 */

import { Finding } from '../../../../../types/finding.types';
import { DnsZone } from './types';

/**
 * Detect unrestricted DNS zone transfers
 *
 * DNS zone transfers allowing any server can expose internal DNS data to attackers.
 *
 * @param dnsZones - Array of DNS zones (if available)
 * @param _includeDetails - Whether to include affected entity details
 * @returns Finding for DNS_ZONE_TRANSFER_UNRESTRICTED
 */
export function detectDnsZoneTransferUnrestricted(
  dnsZones: DnsZone[],
  _includeDetails: boolean
): Finding {
  const affected = dnsZones.filter(
    (zone) =>
      zone.secureSecondaries === 2 || // transferToAnyServer
      zone.secureSecondaries === undefined // Not configured (default may be insecure)
  );

  return {
    type: 'DNS_ZONE_TRANSFER_UNRESTRICTED',
    severity: 'high',
    category: 'network',
    title: 'DNS Zone Transfer Unrestricted',
    description:
      'DNS zones allowing zone transfers to any server. Attackers can enumerate DNS records to map internal network topology.',
    count: affected.length,
    affectedEntities: affected.map((z) => z.name),
    details: {
      zones: affected.map((z) => ({
        name: z.name,
        dn: z.dn,
        secureSecondaries: z.secureSecondaries,
      })),
    },
  };
}
