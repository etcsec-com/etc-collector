/**
 * Groups Security Vulnerability Detector
 *
 * Detects group-related vulnerabilities in AD.
 * Story 1.7: AD Vulnerability Detection Engine
 *
 * Vulnerabilities detected (15):
 * - GPO_MODIFY_RIGHTS (High)
 * - DNS_ADMINS_MEMBER (High)
 * - PRE_WINDOWS_2000_ACCESS (Medium)
 * - OVERSIZED_GROUP_CRITICAL (High)
 * - OVERSIZED_GROUP_HIGH (Medium)
 * - OVERSIZED_GROUP (Medium)
 * - GROUP_EXCESSIVE_MEMBERS (Medium)
 * - DANGEROUS_GROUP_NESTING (Medium)
 * - GROUP_CIRCULAR_NESTING (Medium)
 * - GROUP_EMPTY_PRIVILEGED (Low)
 * - BUILTIN_MODIFIED (High)
 * - GROUP_EVERYONE_IN_PRIVILEGED (Critical)
 * - GROUP_AUTHENTICATED_USERS_PRIVILEGED (High)
 * - GROUP_PROTECTED_USERS_EMPTY (Medium)
 * - EXCESSIVE_PRIVILEGED_ACCOUNTS (Medium)
 */

import { ADUser, ADGroup } from '../../../../../types/ad.types';
import { Finding } from '../../../../../types/finding.types';

// Re-export all detectors
export * from './membership';
export * from './size';
export * from './nesting';
export * from './privileged';

// Import for the main detection function
import {
  detectGpoModifyRights,
  detectDnsAdminsMember,
  detectPreWindows2000Access,
} from './membership';
import {
  detectOversizedGroupCritical,
  detectOversizedGroupHigh,
  detectOversizedGroup,
  detectGroupExcessiveMembers,
} from './size';
import {
  detectDangerousGroupNesting,
  detectGroupCircularNesting,
} from './nesting';
import {
  detectGroupEmptyPrivileged,
  detectBuiltinModified,
  detectGroupEveryoneInPrivileged,
  detectGroupAuthenticatedUsersPrivileged,
  detectGroupProtectedUsersEmpty,
  detectExcessivePrivilegedAccounts,
} from './privileged';

/**
 * Detect all group-related vulnerabilities
 */
export function detectGroupsVulnerabilities(
  users: ADUser[],
  groups: ADGroup[],
  includeDetails: boolean
): Finding[] {
  return [
    // User membership checks
    detectGpoModifyRights(users, includeDetails),
    detectDnsAdminsMember(users, includeDetails),
    detectPreWindows2000Access(users, includeDetails),
    // Group analysis checks
    detectOversizedGroupCritical(groups, includeDetails),
    detectOversizedGroupHigh(groups, includeDetails),
    detectOversizedGroup(groups, includeDetails),
    detectDangerousGroupNesting(groups, includeDetails),
    // Phase 2C: Enhanced detections
    detectGroupEmptyPrivileged(groups, includeDetails),
    detectGroupCircularNesting(groups, includeDetails),
    detectGroupExcessiveMembers(groups, includeDetails),
    detectBuiltinModified(groups, includeDetails),
    // Phase 4: Advanced detections
    detectGroupEveryoneInPrivileged(groups, includeDetails),
    detectGroupAuthenticatedUsersPrivileged(groups, includeDetails),
    detectGroupProtectedUsersEmpty(groups, includeDetails),
    // NEW: Excessive privileged accounts
    detectExcessivePrivilegedAccounts(users, groups, includeDetails),
  ].filter((finding) => finding.count > 0);
}
