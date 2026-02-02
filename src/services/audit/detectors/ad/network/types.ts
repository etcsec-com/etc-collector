/**
 * Network Detector Types
 *
 * Shared type definitions for network infrastructure detectors.
 * Story 1.7: AD Vulnerability Detection Engine
 * Phase 3: Network Infrastructure
 */

/**
 * DNS Zone information (simplified)
 */
export interface DnsZone {
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
export interface ADSite {
  name: string;
  dn: string;
  subnets?: string[];
  servers?: string[];
  [key: string]: unknown;
}

/**
 * AD Subnet information
 */
export interface ADSubnet {
  name: string;
  dn: string;
  site?: string;
  location?: string;
  [key: string]: unknown;
}
