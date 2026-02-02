/**
 * Computers Security Vulnerability Detector
 *
 * Detects computer-related vulnerabilities in AD.
 * Story 1.7: AD Vulnerability Detection Engine
 *
 * Vulnerabilities detected (28):
 * - COMPUTER_CONSTRAINED_DELEGATION (Critical)
 * - COMPUTER_RBCD (Critical)
 * - COMPUTER_IN_ADMIN_GROUP (Critical)
 * - COMPUTER_DCSYNC_RIGHTS (Critical)
 * - COMPUTER_UNCONSTRAINED_DELEGATION (Critical)
 * - COMPUTER_OS_OBSOLETE_XP (Critical)
 * - COMPUTER_OS_OBSOLETE_2003 (Critical)
 * - COMPUTER_STALE_INACTIVE (High)
 * - COMPUTER_PASSWORD_OLD (High)
 * - COMPUTER_WITH_SPNS (High)
 * - COMPUTER_NO_LAPS (High)
 * - COMPUTER_ACL_ABUSE (High)
 * - COMPUTER_OS_OBSOLETE_2008 (High)
 * - COMPUTER_OS_OBSOLETE_VISTA (High)
 * - DC_NOT_IN_DC_OU (High)
 * - COMPUTER_NO_BITLOCKER (High)
 * - COMPUTER_DISABLED_NOT_DELETED (Medium)
 * - COMPUTER_WRONG_OU (Medium)
 * - COMPUTER_WEAK_ENCRYPTION (Medium)
 * - COMPUTER_DESCRIPTION_SENSITIVE (Medium)
 * - COMPUTER_PRE_WINDOWS_2000 (Medium)
 * - COMPUTER_NEVER_LOGGED_ON (Medium)
 * - COMPUTER_DUPLICATE_SPN (Medium)
 * - SERVER_NO_ADMIN_GROUP (Medium)
 * - COMPUTER_LEGACY_PROTOCOL (Medium)
 * - COMPUTER_ADMIN_COUNT (Low)
 * - COMPUTER_SMB_SIGNING_DISABLED (Low)
 * - WORKSTATION_IN_SERVER_OU (Low)
 */

import { ADComputer } from '../../../../../types/ad.types';
import { Finding } from '../../../../../types/finding.types';

// Re-export utilities
export { toTimestamp, filetimeToTimestamp, FILETIME_EPOCH_OFFSET } from './utils';

// Re-export all individual detectors from subdirectories
export {
  detectComputerConstrainedDelegation,
  detectComputerRbcd,
  detectComputerInAdminGroup,
  detectComputerDcsyncRights,
  detectComputerUnconstrainedDelegation,
} from './delegation';

export {
  detectComputerStaleInactive,
  detectComputerPasswordOld,
  detectComputerDisabledNotDeleted,
  detectComputerNeverLoggedOn,
  detectComputerPreCreated,
  detectComputerAdminCount,
} from './status';

export {
  detectComputerWithSpns,
  detectComputerNoLaps,
  detectComputerAclAbuse,
  detectComputerWeakEncryption,
  detectComputerSmbSigningDisabled,
  detectComputerNoBitlocker,
  detectComputerLegacyProtocol,
  detectComputerDuplicateSpn,
} from './security';

export {
  detectComputerWrongOu,
  detectDcNotInDcOu,
  detectWorkstationInServerOu,
  detectServerNoAdminGroup,
} from './organization';

export { detectComputerObsoleteOS, OBSOLETE_OS_PATTERNS } from './obsolete-os';

export {
  detectComputerDescriptionSensitive,
  detectComputerPreWindows2000,
} from './other';

// Import for aggregate function
import {
  detectComputerConstrainedDelegation,
  detectComputerRbcd,
  detectComputerInAdminGroup,
  detectComputerDcsyncRights,
  detectComputerUnconstrainedDelegation,
} from './delegation';

import {
  detectComputerStaleInactive,
  detectComputerPasswordOld,
  detectComputerDisabledNotDeleted,
  detectComputerNeverLoggedOn,
  detectComputerPreCreated,
  detectComputerAdminCount,
} from './status';

import {
  detectComputerWithSpns,
  detectComputerNoLaps,
  detectComputerAclAbuse,
  detectComputerWeakEncryption,
  detectComputerSmbSigningDisabled,
  detectComputerNoBitlocker,
  detectComputerLegacyProtocol,
  detectComputerDuplicateSpn,
} from './security';

import {
  detectComputerWrongOu,
  detectDcNotInDcOu,
  detectWorkstationInServerOu,
  detectServerNoAdminGroup,
} from './organization';

import { detectComputerObsoleteOS } from './obsolete-os';

import {
  detectComputerDescriptionSensitive,
  detectComputerPreWindows2000,
} from './other';

/**
 * Detect all computer-related vulnerabilities
 */
export function detectComputersVulnerabilities(
  computers: ADComputer[],
  includeDetails: boolean
): Finding[] {
  // Get obsolete OS findings (returns array)
  const obsoleteOsFindings = detectComputerObsoleteOS(computers, includeDetails);

  return [
    ...obsoleteOsFindings,
    detectComputerNeverLoggedOn(computers, includeDetails),
    detectComputerPreCreated(computers, includeDetails),
    detectComputerConstrainedDelegation(computers, includeDetails),
    detectComputerRbcd(computers, includeDetails),
    detectComputerInAdminGroup(computers, includeDetails),
    detectComputerDcsyncRights(computers, includeDetails),
    detectComputerUnconstrainedDelegation(computers, includeDetails),
    detectComputerStaleInactive(computers, includeDetails),
    detectComputerPasswordOld(computers, includeDetails),
    detectComputerWithSpns(computers, includeDetails),
    detectComputerNoLaps(computers, includeDetails),
    detectComputerAclAbuse(computers, includeDetails),
    detectComputerDisabledNotDeleted(computers, includeDetails),
    detectComputerWrongOu(computers, includeDetails),
    detectComputerWeakEncryption(computers, includeDetails),
    detectComputerDescriptionSensitive(computers, includeDetails),
    detectComputerPreWindows2000(computers, includeDetails),
    detectComputerAdminCount(computers, includeDetails),
    detectComputerSmbSigningDisabled(computers, includeDetails),
    // Phase 2C: Enhanced detections
    detectDcNotInDcOu(computers, includeDetails),
    detectComputerDuplicateSpn(computers, includeDetails),
    detectServerNoAdminGroup(computers, includeDetails),
    detectWorkstationInServerOu(computers, includeDetails),
    // Phase 4: Advanced detections
    detectComputerNoBitlocker(computers, includeDetails),
    detectComputerLegacyProtocol(computers, includeDetails),
  ].filter((finding) => {
    // Include findings with count > 0
    if (finding.count > 0) return true;
    // Also include findings with debug details (for troubleshooting)
    if (finding.details?.['debug']) return true;
    return false;
  });
}
