/**
 * Attack Paths Vulnerability Detector
 *
 * Analyzes privilege escalation paths in Active Directory by combining:
 * - Group membership chains
 * - ACL-based attack vectors
 * - Delegation relationships
 * - Service account risks
 *
 * Phase 2: Attack Paths Detection
 *
 * Vulnerabilities detected (10):
 * CRITICAL (4):
 * - PATH_KERBEROASTING_TO_DA: Kerberoastable user in DA path
 * - PATH_ACL_TO_DA: ACL chain to Domain Admin
 * - PATH_SERVICE_TO_DA: Service account with path to DA
 * - PATH_CERTIFICATE_ESC: ADCS template vulnerability to DA
 *
 * HIGH (5):
 * - PATH_ASREP_TO_ADMIN: AS-REP roastable user in admin group
 * - PATH_DELEGATION_CHAIN: Delegation chain to privileged target
 * - PATH_NESTED_ADMIN: Excessive group nesting to admin
 * - PATH_COMPUTER_TAKEOVER: RBCD attack path
 * - PATH_GPO_TO_DA: GPO modification leads to DA
 *
 * MEDIUM (1):
 * - PATH_TRUST_LATERAL: Trust enables lateral movement
 */

import { ADUser, ADGroup, ADComputer, AclEntry } from '../../../../../types/ad.types';
import { Finding } from '../../../../../types/finding.types';
import { ADGPO } from '../../../../../types/gpo.types';
import { ADTrustExtended } from '../../../../../types/trust.types';

// Re-export all detectors from submodules
export * from './critical';
export * from './high';
export * from './medium';

// Import detectors for the main function
import {
  detectPathKerberoastingToDA,
  detectPathAclToDA,
  detectPathServiceToDA,
  detectPathCertificateEsc,
} from './critical';

import {
  detectPathAsrepToAdmin,
  detectPathDelegationChain,
  detectPathNestedAdmin,
  detectPathComputerTakeover,
  detectPathGpoToDA,
} from './high';

import { detectPathTrustLateral } from './medium';

/**
 * Detect all attack path vulnerabilities
 */
export function detectAttackPathVulnerabilities(
  users: ADUser[],
  groups: ADGroup[],
  computers: ADComputer[],
  aclEntries: AclEntry[],
  gpos: ADGPO[],
  trusts: ADTrustExtended[],
  templates: any[],
  includeDetails: boolean
): Finding[] {
  return [
    // Critical
    detectPathKerberoastingToDA(users, groups, computers, includeDetails),
    detectPathAclToDA(users, groups, computers, aclEntries, includeDetails),
    detectPathServiceToDA(users, groups, computers, aclEntries, includeDetails),
    detectPathCertificateEsc(templates, users, groups, computers, includeDetails),
    // High
    detectPathAsrepToAdmin(users, groups, computers, includeDetails),
    detectPathDelegationChain(users, computers, groups, includeDetails),
    detectPathNestedAdmin(users, groups, includeDetails),
    detectPathComputerTakeover(computers, users, groups, includeDetails),
    detectPathGpoToDA(gpos, aclEntries, includeDetails),
    // Medium
    detectPathTrustLateral(trusts, includeDetails),
  ].filter((finding) => finding.count > 0);
}
