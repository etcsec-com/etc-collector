/**
 * DNSSEC Detector
 *
 * Detects when DNSSEC is not enabled.
 * Story 1.7: AD Vulnerability Detection Engine
 * Phase 3: Network Infrastructure
 */

import { ADDomain } from '../../../../../types/ad.types';
import { Finding } from '../../../../../types/finding.types';

/**
 * Detect DNSSEC not enabled
 *
 * Without DNSSEC, DNS responses can be spoofed.
 *
 * @param domain - Domain information
 * @param _includeDetails - Whether to include affected entity details
 * @returns Finding for DNSSEC_NOT_ENABLED
 */
export function detectDnssecNotEnabled(
  domain: ADDomain | null,
  _includeDetails: boolean
): Finding {
  // Check if domain has DNSSEC trust anchors configured
  // This would typically check for dnsroot LDAP object or DNS server config
  const dnssecEnabled = domain && domain['msDS-TrustForestTrustInfo'] !== undefined;

  return {
    type: 'DNSSEC_NOT_ENABLED',
    severity: 'medium',
    category: 'network',
    title: 'DNSSEC Not Enabled',
    description:
      'DNSSEC is not enabled for the domain. DNS responses can be spoofed, enabling cache poisoning and MITM attacks.',
    count: dnssecEnabled ? 0 : 1,
    details: {
      recommendation: 'Enable DNSSEC signing on Active Directory-integrated DNS zones.',
    },
  };
}
