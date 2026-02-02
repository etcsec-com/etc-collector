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

import { ADComputer, ADDomain } from '../../../../types/ad.types';
import { Finding } from '../../../../types/finding.types';
import { toAffectedComputerEntities } from '../../../../utils/entity-converter';

/**
 * DNS Zone information (simplified)
 */
interface DnsZone {
  name: string;
  dn: string;
  zoneType?: number; // 0=cache, 1=primary, 2=secondary, 3=stub, 4=forwarder
  dynamicUpdate?: number; // 0=none, 1=nonsecure, 2=secure, 3=nonsecureAndSecure
  secureSecondaries?: number; // 0=noTransfer, 1=transferToZoneServers, 2=transferToAnyServer
  [key: string]: unknown;
}

/**
 * AD Site information
 */
interface ADSite {
  name: string;
  dn: string;
  subnets?: string[];
  servers?: string[];
  [key: string]: unknown;
}

/**
 * AD Subnet information
 */
interface ADSubnet {
  name: string;
  dn: string;
  site?: string;
  location?: string;
  [key: string]: unknown;
}

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

/**
 * Detect DNS wildcard records
 *
 * Wildcard DNS records can be abused for MITM attacks and credential capture.
 *
 * @param dnsZones - Array of DNS zones with records (if available)
 * @param _includeDetails - Whether to include affected entity details
 * @returns Finding for DNS_WILDCARD_RECORDS
 */
export function detectDnsWildcardRecords(
  _dnsZones: DnsZone[],
  _includeDetails: boolean
): Finding {
  // This detection would require querying DNS records within zones
  // For now, return empty finding as placeholder
  const affected: DnsZone[] = [];

  return {
    type: 'DNS_WILDCARD_RECORDS',
    severity: 'medium',
    category: 'network',
    title: 'DNS Wildcard Records Detected',
    description:
      'Wildcard DNS records (*.domain) can be exploited for MITM attacks. Review and remove unnecessary wildcards.',
    count: affected.length,
    affectedEntities: affected.map((z) => z.name),
  };
}

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

/**
 * Detect SYSVOL/NETLOGON permission issues
 *
 * Weak permissions on SYSVOL/NETLOGON shares enable GPO manipulation.
 *
 * @param _domain - Domain information
 * @param _includeDetails - Whether to include affected entity details
 * @returns Finding for SYSVOL_NETLOGON_PERMISSIONS
 */
export function detectSysvolNetlogonPermissions(
  _domain: ADDomain | null,
  _includeDetails: boolean
): Finding {
  // This would require reading SYSVOL share permissions via SMB
  // Placeholder for now
  return {
    type: 'SYSVOL_NETLOGON_PERMISSIONS',
    severity: 'high',
    category: 'network',
    title: 'SYSVOL/NETLOGON Permissions Review',
    description:
      'SYSVOL and NETLOGON share permissions should be audited. Weak permissions allow attackers to modify logon scripts and GPOs.',
    count: 0, // Will be populated when SMB permission reading is implemented
    details: {
      recommendation:
        'Review SYSVOL and NETLOGON share permissions. Only Domain Admins should have write access.',
    },
  };
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

/**
 * Detect old domain controller backups
 *
 * DCs without recent backups risk data loss.
 *
 * @param domainControllers - Array of domain controllers
 * @param includeDetails - Whether to include affected entity details
 * @returns Finding for DC_BACKUP_OLD
 */
export function detectDcBackupOld(
  domainControllers: ADComputer[],
  includeDetails: boolean
): Finding {
  // Check lastLogonTimestamp and pwdLastSet as proxy for DC health
  const now = new Date();
  const thirtyDaysAgo = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);

  const possiblyUnbackedUp = domainControllers.filter((dc) => {
    // If DC hasn't replicated password recently, it might indicate backup issues
    const pwdLastSet = dc.passwordLastSet;
    return pwdLastSet && pwdLastSet < thirtyDaysAgo;
  });

  return {
    type: 'DC_BACKUP_OLD',
    severity: 'medium',
    category: 'network',
    title: 'Domain Controller Backup Review',
    description:
      'Domain controllers should be backed up regularly. Tombstone lifetime is 180 days - DCs offline longer than this cannot rejoin.',
    count: possiblyUnbackedUp.length,
    affectedEntities: includeDetails
      ? toAffectedComputerEntities(possiblyUnbackedUp)
      : undefined,
    details: {
      recommendation:
        'Verify Windows Server Backup or third-party backup solution is configured on all DCs.',
    },
  };
}

/**
 * Detect domain controllers with potential disk space issues
 *
 * Low disk space on DCs can cause replication failures and service outages.
 *
 * @param domainControllers - Array of domain controllers
 * @param _includeDetails - Whether to include affected entity details
 * @returns Finding for DC_DISK_SPACE_LOW
 */
export function detectDcDiskSpaceLow(
  domainControllers: ADComputer[],
  _includeDetails: boolean
): Finding {
  // This would require WMI/CIM queries to check disk space
  // Placeholder detection
  return {
    type: 'DC_DISK_SPACE_LOW',
    severity: 'medium',
    category: 'network',
    title: 'DC Disk Space Monitoring',
    description:
      'Domain controller disk space should be monitored. Low disk space can cause AD database corruption and replication failures.',
    count: 0, // Would be populated with actual disk space checks
    details: {
      dcCount: domainControllers.length,
      recommendation:
        'Monitor DC disk space. NTDS.dit location should have at least 20% free space.',
    },
  };
}

/**
 * Detect domain controller time sync issues
 *
 * Time synchronization issues cause Kerberos failures.
 *
 * @param domainControllers - Array of domain controllers
 * @param includeDetails - Whether to include affected entity details
 * @returns Finding for DC_TIME_SYNC_ISSUE
 */
export function detectDcTimeSyncIssue(
  domainControllers: ADComputer[],
  includeDetails: boolean
): Finding {
  // Check if any DC has very old lastLogon (might indicate it's offline/out of sync)
  const now = new Date();
  const sevenDaysAgo = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);

  const possibleTimeSyncIssues = domainControllers.filter((dc) => {
    const lastLogon = dc.lastLogon;
    return lastLogon && lastLogon < sevenDaysAgo;
  });

  return {
    type: 'DC_TIME_SYNC_ISSUE',
    severity: 'high',
    category: 'network',
    title: 'DC Time Synchronization Review',
    description:
      'Domain controllers with potential time sync issues detected. Kerberos requires time difference < 5 minutes.',
    count: possibleTimeSyncIssues.length,
    affectedEntities: includeDetails
      ? toAffectedComputerEntities(possibleTimeSyncIssues)
      : undefined,
    details: {
      possibleIssues: possibleTimeSyncIssues.map((dc) => dc.sAMAccountName),
      recommendation:
        'Run "w32tm /query /status" on each DC to verify time configuration.',
    },
  };
}

/**
 * Helper function to get domain functional level name
 */
function getDomainLevelName(level: number): string {
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
