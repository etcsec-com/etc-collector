/**
 * Password Security Vulnerability Detector
 *
 * Detects password-related vulnerabilities in AD users.
 * Story 1.7: AD Vulnerability Detection Engine
 *
 * Vulnerabilities detected (11):
 * - PASSWORD_NOT_REQUIRED (Critical)
 * - REVERSIBLE_ENCRYPTION (Critical)
 * - PASSWORD_NEVER_EXPIRES (Critical)
 * - PASSWORD_VERY_OLD (Medium)
 * - PASSWORD_IN_DESCRIPTION (High)
 * - USER_CANNOT_CHANGE_PASSWORD (Medium)
 * - UNIX_USER_PASSWORD (Critical)
 * - WEAK_PASSWORD_POLICY (High - domain level)
 * - PASSWORD_CLEARTEXT_STORAGE (Critical) - Phase 3
 * - PASSWORD_COMMON_PATTERNS (High) - Phase 3
 * - PASSWORD_DICT_ATTACK_RISK (Medium) - Phase 3
 */

import { ADUser } from '../../../../../types/ad.types';
import { Finding } from '../../../../../types/finding.types';

// Re-export all individual detectors
export { detectPasswordNotRequired } from './password-not-required.detector';
export { detectReversibleEncryption } from './reversible-encryption.detector';
export { detectPasswordNeverExpires } from './password-never-expires.detector';
export { detectPasswordVeryOld } from './password-very-old.detector';
export { detectPasswordInDescription } from './password-in-description.detector';
export { detectUserCannotChangePassword } from './user-cannot-change-password.detector';
export { detectUnixUserPassword } from './unix-user-password.detector';
export { detectPasswordCleartextStorage } from './password-cleartext-storage.detector';
export { detectPasswordCommonPatterns } from './password-common-patterns.detector';
export { detectPasswordDictAttackRisk } from './password-dict-attack-risk.detector';

// Import for the main detection function
import { detectPasswordNotRequired } from './password-not-required.detector';
import { detectReversibleEncryption } from './reversible-encryption.detector';
import { detectPasswordNeverExpires } from './password-never-expires.detector';
import { detectPasswordVeryOld } from './password-very-old.detector';
import { detectPasswordInDescription } from './password-in-description.detector';
import { detectUserCannotChangePassword } from './user-cannot-change-password.detector';
import { detectUnixUserPassword } from './unix-user-password.detector';
import { detectPasswordCleartextStorage } from './password-cleartext-storage.detector';
import { detectPasswordCommonPatterns } from './password-common-patterns.detector';
import { detectPasswordDictAttackRisk } from './password-dict-attack-risk.detector';

/**
 * Detect all password-related vulnerabilities
 */
export function detectPasswordVulnerabilities(users: ADUser[], includeDetails: boolean): Finding[] {
  return [
    detectPasswordNotRequired(users, includeDetails),
    detectReversibleEncryption(users, includeDetails),
    detectPasswordNeverExpires(users, includeDetails),
    detectPasswordVeryOld(users, includeDetails),
    detectPasswordInDescription(users, includeDetails),
    detectUserCannotChangePassword(users, includeDetails),
    detectUnixUserPassword(users, includeDetails),
    // Phase 3 additions
    detectPasswordCleartextStorage(users, includeDetails),
    detectPasswordCommonPatterns(users, includeDetails),
    detectPasswordDictAttackRisk(users, includeDetails),
  ].filter((finding) => finding.count > 0); // Only return findings with affected entities
}
