/**
 * GPO Security Vulnerability Detector
 *
 * Analyzes Group Policy Objects for security misconfigurations.
 *
 * Vulnerabilities detected (9):
 * CRITICAL (1) - Phase 4:
 * - GPO_PASSWORD_IN_SYSVOL: Passwords found in GPO preferences
 *
 * HIGH (2):
 * - GPO_DANGEROUS_PERMISSIONS: Non-admin can edit GPO linked to sensitive OUs
 * - GPO_WEAK_PASSWORD_POLICY: GPO with password length < 12 characters
 *
 * MEDIUM (5):
 * - GPO_LAPS_NOT_DEPLOYED: No LAPS deployment GPO found
 * - GPO_DISABLED_BUT_LINKED: GPO disabled but still linked
 * - GPO_NO_SECURITY_FILTERING: GPO without security filtering
 * - GPO_AUTHENTICATED_USERS_APPLY: GPO applies to all Authenticated Users
 * - GPO_ORPHANED: Orphaned GPO (Phase 4)
 *
 * LOW (1):
 * - GPO_UNLINKED: GPO exists but not linked anywhere
 */

import { Finding } from '../../../../../types/finding.types';
import { ADGPO, GPOLink, GPOAclEntry } from '../../../../../types/gpo.types';

// Re-export all detectors
export { detectGpoDangerousPermissions } from './dangerous-permissions';
export { detectGpoLapsNotDeployed } from './laps-not-deployed';
export { detectGpoWeakPasswordPolicy } from './weak-password-policy';
export { detectGpoUnlinked } from './unlinked';
export { detectGpoDisabledButLinked } from './disabled-but-linked';
export { detectGpoNoSecurityFiltering } from './no-security-filtering';
export { detectGpoAuthenticatedUsersApply } from './authenticated-users-apply';
export { detectGpoPasswordInSysvol } from './password-in-sysvol';
export { detectGpoOrphaned } from './orphaned';

// Re-export shared types
export * from './types';

// Import for the main detection function
import { detectGpoDangerousPermissions } from './dangerous-permissions';
import { detectGpoLapsNotDeployed } from './laps-not-deployed';
import { detectGpoWeakPasswordPolicy } from './weak-password-policy';
import { detectGpoUnlinked } from './unlinked';
import { detectGpoDisabledButLinked } from './disabled-but-linked';
import { detectGpoNoSecurityFiltering } from './no-security-filtering';
import { detectGpoAuthenticatedUsersApply } from './authenticated-users-apply';
import { detectGpoPasswordInSysvol } from './password-in-sysvol';
import { detectGpoOrphaned } from './orphaned';

/**
 * Aggregate function: Detect all GPO vulnerabilities
 */
export function detectGpoVulnerabilities(
  gpos: ADGPO[],
  links: GPOLink[],
  domainPasswordPolicy: { minPasswordLength?: number } | null,
  includeDetails: boolean,
  gpoAcls: GPOAclEntry[] = []
): Finding[] {
  return [
    detectGpoDangerousPermissions(gpos, links, includeDetails),
    detectGpoLapsNotDeployed(gpos, links, includeDetails),
    detectGpoWeakPasswordPolicy(gpos, links, domainPasswordPolicy, includeDetails),
    detectGpoUnlinked(gpos, links, includeDetails),
    detectGpoDisabledButLinked(gpos, links, includeDetails),
    detectGpoNoSecurityFiltering(gpos, links, gpoAcls, includeDetails),
    detectGpoAuthenticatedUsersApply(gpos, links, gpoAcls, includeDetails),
    // Phase 4: Advanced GPO detections
    detectGpoPasswordInSysvol(gpos, links, includeDetails),
    detectGpoOrphaned(gpos, links, includeDetails),
  ].filter((finding) => finding.count > 0 || finding.details?.['note']);
}
