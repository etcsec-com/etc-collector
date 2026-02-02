/**
 * Network Infrastructure Detector
 *
 * Detects network-related security issues in Active Directory:
 * - DNS misconfigurations
 * - Site topology issues
 * - SYSVOL/DFSR problems
 * - Domain Controller health issues
 *
 * Story 1.7: AD Vulnerability Detection Engine
 * Phase 3: Network Infrastructure (12 vulnerabilities)
 */

import { ADComputer, ADDomain } from '../../../../../types/ad.types';
import { Finding } from '../../../../../types/finding.types';

// Import types
import { DnsZone, ADSite, ADSubnet } from './types';

// Import individual detectors
import { detectDnsZoneTransferUnrestricted } from './dns-zone-transfer.detector';
import { detectDnsDynamicUpdateInsecure } from './dns-dynamic-update.detector';
import { detectDnsWildcardRecords } from './dns-wildcard.detector';
import { detectDnssecNotEnabled } from './dnssec.detector';
import { detectNtpNotConfigured } from './ntp.detector';
import { detectSiteTopologyIssues } from './site-topology.detector';
import { detectSubnetMissing } from './subnet-missing.detector';
import { detectSysvolNetlogonPermissions } from './sysvol-netlogon.detector';
import { detectDfsrNotConfigured } from './dfsr.detector';
import { detectDcBackupOld } from './dc-backup.detector';
import { detectDcDiskSpaceLow } from './dc-disk-space.detector';
import { detectDcTimeSyncIssue } from './dc-time-sync.detector';

// Re-export types
export { DnsZone, ADSite, ADSubnet } from './types';

// Re-export individual detectors
export { detectDnsZoneTransferUnrestricted } from './dns-zone-transfer.detector';
export { detectDnsDynamicUpdateInsecure } from './dns-dynamic-update.detector';
export { detectDnsWildcardRecords } from './dns-wildcard.detector';
export { detectDnssecNotEnabled } from './dnssec.detector';
export { detectNtpNotConfigured } from './ntp.detector';
export { detectSiteTopologyIssues } from './site-topology.detector';
export { detectSubnetMissing } from './subnet-missing.detector';
export { detectSysvolNetlogonPermissions } from './sysvol-netlogon.detector';
export { detectDfsrNotConfigured, getDomainLevelName } from './dfsr.detector';
export { detectDcBackupOld } from './dc-backup.detector';
export { detectDcDiskSpaceLow } from './dc-disk-space.detector';
export { detectDcTimeSyncIssue } from './dc-time-sync.detector';

/**
 * Detect all network-related vulnerabilities
 *
 * @param computers - Array of AD computers
 * @param domain - Domain information
 * @param domainControllers - Array of domain controllers
 * @param dnsZones - Array of DNS zones (if available)
 * @param sites - Array of AD sites (if available)
 * @param subnets - Array of AD subnets (if available)
 * @param includeDetails - Whether to include affected entity details
 * @returns Array of findings
 */
export function detectNetworkVulnerabilities(
  _computers: ADComputer[],
  domain: ADDomain | null,
  domainControllers: ADComputer[],
  dnsZones: DnsZone[] = [],
  sites: ADSite[] = [],
  subnets: ADSubnet[] = [],
  includeDetails: boolean
): Finding[] {
  const findings: Finding[] = [];

  // DNS detections
  findings.push(detectDnsZoneTransferUnrestricted(dnsZones, includeDetails));
  findings.push(detectDnsDynamicUpdateInsecure(dnsZones, includeDetails));
  findings.push(detectDnsWildcardRecords(dnsZones, includeDetails));
  findings.push(detectDnssecNotEnabled(domain, includeDetails));

  // Infrastructure detections
  findings.push(detectNtpNotConfigured(domainControllers, includeDetails));
  findings.push(detectSiteTopologyIssues(sites, includeDetails));
  findings.push(detectSubnetMissing(sites, subnets, includeDetails));
  findings.push(detectSysvolNetlogonPermissions(domain, includeDetails));

  // DFSR/DC health detections
  findings.push(detectDfsrNotConfigured(domain, includeDetails));
  findings.push(detectDcBackupOld(domainControllers, includeDetails));
  findings.push(detectDcDiskSpaceLow(domainControllers, includeDetails));
  findings.push(detectDcTimeSyncIssue(domainControllers, includeDetails));

  // Filter out findings with count=0
  return findings.filter((f) => f.count > 0);
}
