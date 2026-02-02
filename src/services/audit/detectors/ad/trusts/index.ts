/**
 * Domain Trusts Security Vulnerability Detector
 *
 * Analyzes trust relationships for security risks.
 *
 * Vulnerabilities detected (7):
 * HIGH (4):
 * - TRUST_SID_FILTERING_DISABLED: SID history attacks possible
 * - TRUST_EXTERNAL_NO_SELECTIVE_AUTH: External trust without selective authentication
 * - TRUST_AES_DISABLED: AES encryption not supported on trust
 * - TRUST_RC4_ONLY: Trust only supports weak RC4 encryption
 *
 * MEDIUM (3):
 * - TRUST_BIDIRECTIONAL: Two-way trust enables lateral movement
 * - TRUST_FOREST_TRANSITIVE: Transitive forest trust increases attack surface
 * - TRUST_INACTIVE: Trust relationship not modified in 180+ days
 */

import { Finding } from '../../../../../types/finding.types';
import { ADTrustExtended } from '../../../../../types/trust.types';

// Re-export individual detectors
export { detectTrustSidFilteringDisabled } from './sid-filtering-disabled';
export { detectTrustExternalNoSelectiveAuth } from './external-no-selective-auth';
export { detectTrustBidirectional } from './bidirectional';
export { detectTrustForestTransitive } from './forest-transitive';
export { detectTrustAesDisabled } from './aes-disabled';
export { detectTrustRc4Only } from './rc4-only';
export { detectTrustInactive } from './inactive';

// Import for aggregate function
import { detectTrustSidFilteringDisabled } from './sid-filtering-disabled';
import { detectTrustExternalNoSelectiveAuth } from './external-no-selective-auth';
import { detectTrustBidirectional } from './bidirectional';
import { detectTrustForestTransitive } from './forest-transitive';
import { detectTrustAesDisabled } from './aes-disabled';
import { detectTrustRc4Only } from './rc4-only';
import { detectTrustInactive } from './inactive';

/**
 * Aggregate function: Detect all trust vulnerabilities
 */
export function detectTrustVulnerabilities(
  trusts: ADTrustExtended[],
  includeDetails: boolean
): Finding[] {
  return [
    detectTrustSidFilteringDisabled(trusts, includeDetails),
    detectTrustExternalNoSelectiveAuth(trusts, includeDetails),
    detectTrustBidirectional(trusts, includeDetails),
    detectTrustForestTransitive(trusts, includeDetails),
    detectTrustAesDisabled(trusts, includeDetails),
    detectTrustRc4Only(trusts, includeDetails),
    detectTrustInactive(trusts, includeDetails),
  ].filter((finding) => finding.count > 0);
}
