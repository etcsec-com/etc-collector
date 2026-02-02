/**
 * Permissions & ACL Security Vulnerability Detector
 *
 * Detects ACL-related vulnerabilities in AD.
 * Story 1.7: AD Vulnerability Detection Engine
 *
 * Vulnerabilities detected (16):
 * CRITICAL (1):
 * - ACL_DS_REPLICATION_GET_CHANGES
 *
 * HIGH (5):
 * - ACL_GENERICALL
 * - ACL_WRITEDACL
 * - ACL_WRITEOWNER
 * - ACL_SELF_MEMBERSHIP
 * - COMPUTER_ACL_GENERICALL
 *
 * MEDIUM (10):
 * - ACL_GENERICWRITE
 * - ACL_FORCECHANGEPASSWORD
 * - EVERYONE_IN_ACL
 * - WRITESPN_ABUSE
 * - GPO_LINK_POISONING
 * - ADMINSDHOLDER_BACKDOOR
 * - ACL_ADD_MEMBER
 * - ACL_WRITE_PROPERTY_EXTENDED
 * - ACL_USER_FORCE_CHANGE_PASSWORD
 * - ACL_COMPUTER_WRITE_VALIDATED_DNS
 */

import { AclEntry } from '../../../../../types/ad.types';
import { Finding } from '../../../../../types/finding.types';

// Re-export utilities
export { getUniqueObjects } from './utils';

// Re-export all detectors
export * from './dangerous';
export * from './moderate';
export * from './computer';

// Import for the main detection function
import {
  detectAclGenericAll,
  detectAclWriteDacl,
  detectAclWriteOwner,
  detectAclSelfMembership,
  detectAclDsReplicationGetChanges,
} from './dangerous';
import {
  detectAclGenericWrite,
  detectAclForceChangePassword,
  detectEveryoneInAcl,
  detectWriteSpnAbuse,
  detectGpoLinkPoisoning,
  detectAdminSdHolderBackdoor,
  detectAclAddMember,
  detectAclWritePropertyExtended,
  detectAclUserForceChangePassword,
  detectAclComputerWriteValidatedDns,
} from './moderate';
import { detectComputerAclGenericAll } from './computer';

/**
 * Detect all permission-related vulnerabilities
 *
 * @param aclEntries - Array of ACL entries
 * @param includeDetails - Whether to include affected entity details
 * @param computerDns - Optional array of computer DNs for accurate COMPUTER_ACL_GENERICALL detection
 */
export function detectPermissionsVulnerabilities(
  aclEntries: AclEntry[],
  includeDetails: boolean,
  computerDns?: string[]
): Finding[] {
  return [
    // High
    detectAclGenericAll(aclEntries, includeDetails),
    detectComputerAclGenericAll(aclEntries, includeDetails, computerDns),
    detectAclWriteDacl(aclEntries, includeDetails),
    detectAclWriteOwner(aclEntries, includeDetails),
    // Medium
    detectAclGenericWrite(aclEntries, includeDetails),
    detectAclForceChangePassword(aclEntries, includeDetails),
    detectEveryoneInAcl(aclEntries, includeDetails),
    detectWriteSpnAbuse(aclEntries, includeDetails),
    detectGpoLinkPoisoning(aclEntries, includeDetails),
    detectAdminSdHolderBackdoor(aclEntries, includeDetails),
    // Phase 4: Advanced ACL detections
    detectAclSelfMembership(aclEntries, includeDetails),
    detectAclAddMember(aclEntries, includeDetails),
    detectAclWritePropertyExtended(aclEntries, includeDetails),
    detectAclDsReplicationGetChanges(aclEntries, includeDetails),
    detectAclUserForceChangePassword(aclEntries, includeDetails),
    detectAclComputerWriteValidatedDns(aclEntries, includeDetails),
  ].filter((finding) => finding.count > 0);
}
