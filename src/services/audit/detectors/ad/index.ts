/**
 * Active Directory Vulnerability Detectors
 *
 * Exports all AD vulnerability detection functions
 * Story 1.7: AD Vulnerability Detection Engine
 *
 * Total: 216 vulnerabilities across 14 categories
 * - Password: 10 vulnerabilities (+3 Phase 3)
 * - Kerberos: 12 vulnerabilities (+4 Phase 4)
 * - Accounts: 31 vulnerabilities (+3 Phase 4)
 * - Groups: 14 vulnerabilities (+3 Phase 4)
 * - Computers: 28 vulnerabilities (+2 Phase 4)
 * - Advanced: 35 vulnerabilities (+3 Phase 4)
 * - Permissions: 15 vulnerabilities (+6 Phase 4)
 * - ADCS: 11 vulnerabilities (ESC1-ESC11)
 * - GPO: 9 vulnerabilities (+2 Phase 4)
 * - Trusts: 7 vulnerabilities
 * - Attack Paths: 10 vulnerabilities (Phase 2A)
 * - Monitoring: 8 vulnerabilities (Phase 2B)
 * - Compliance: 23 vulnerabilities (+8 Industry Frameworks: PCI-DSS, SOC2, GDPR, SOX, DORA, HIPAA, ISO27001)
 * - Network: 12 vulnerabilities (Phase 3)
 */

// Password detectors
export * from './password.detector';

// Kerberos detectors
export * from './kerberos.detector';

// Accounts detectors
export * from './accounts.detector';

// Groups detectors
export * from './groups.detector';

// Computers detectors
export * from './computers.detector';

// Advanced detectors (excluding ESC functions which are in adcs.detector)
export {
  detectShadowCredentials,
  detectRbcdAbuse,
  detectLapsNotDeployed,
  detectLapsPasswordReadable,
  detectLapsLegacyAttribute,
  detectLapsPasswordSet,
  detectLapsPasswordLeaked,
  detectDuplicateSpn,
  detectWeakPasswordPolicy,
  detectWeakKerberosPolicy,
  detectMachineAccountQuotaAbuse,
  detectDelegationPrivilege,
  detectAdcsWeakPermissions,
  detectDangerousLogonScripts,
  detectForeignSecurityPrincipals,
  detectReplicationRights,
  detectDcsyncCapable,
  detectNtlmRelayOpportunity,
  detectAdvancedVulnerabilities,
} from './advanced.detector';

// Permissions detectors
export * from './permissions.detector';

// ADCS detectors (ESC1-ESC8) - replaces legacy ESC functions from advanced.detector
export * from './adcs.detector';

// GPO detectors
export * from './gpo.detector';

// Trusts detectors
export * from './trusts.detector';

// Attack Paths detectors (Phase 2A)
export * from './attack-paths.detector';

// Monitoring detectors (Phase 2B)
export * from './monitoring.detector';

// Compliance detectors (Phase 3)
export * from './compliance.detector';

// Network detectors (Phase 3)
export * from './network.detector';
