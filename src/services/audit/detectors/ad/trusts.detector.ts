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

import { Finding } from '../../../../types/finding.types';
import {
  ADTrustExtended,
  TRUST_ATTRIBUTE_QUARANTINED_DOMAIN,
  TRUST_ATTRIBUTE_CROSS_ORGANIZATION,
  TRUST_ATTRIBUTE_FOREST_TRANSITIVE,
  TRUST_ATTRIBUTE_WITHIN_FOREST,
  TRUST_DIRECTION_BIDIRECTIONAL,
} from '../../../../types/trust.types';

/**
 * TRUST_SID_FILTERING_DISABLED: SID filtering not enabled
 * Allows SID history injection attacks across trust boundary
 */
export function detectTrustSidFilteringDisabled(
  trusts: ADTrustExtended[],
  includeDetails: boolean
): Finding {
  // SID filtering should be enabled (TRUST_ATTRIBUTE_QUARANTINED_DOMAIN)
  // except for trusts within the same forest
  const affected = trusts.filter((t) => {
    // Skip intra-forest trusts (parent-child) - SID filtering not applicable
    if ((t.trustAttributes & TRUST_ATTRIBUTE_WITHIN_FOREST) !== 0) {
      return false;
    }

    // Check if SID filtering is disabled (QUARANTINED_DOMAIN flag NOT set)
    const sidFilteringDisabled = (t.trustAttributes & TRUST_ATTRIBUTE_QUARANTINED_DOMAIN) === 0;

    return sidFilteringDisabled;
  });

  return {
    type: 'TRUST_SID_FILTERING_DISABLED',
    severity: 'high',
    category: 'trusts',
    title: 'SID Filtering Disabled on Trust',
    description:
      'Trust relationships without SID filtering allow SID history injection attacks, enabling attackers to impersonate any user in the trusted domain.',
    count: affected.length,
    affectedEntities: includeDetails ? affected.map((t) => t.name) : undefined,
    details:
      affected.length > 0
        ? {
            recommendation: 'Enable SID filtering (quarantine) on external and forest trusts.',
          }
        : undefined,
  };
}

/**
 * TRUST_EXTERNAL_NO_SELECTIVE_AUTH: External trust without selective authentication
 * All users from trusted domain can authenticate to any resource
 */
export function detectTrustExternalNoSelectiveAuth(
  trusts: ADTrustExtended[],
  includeDetails: boolean
): Finding {
  // Selective authentication should be enabled for external trusts
  // to limit which users can authenticate
  const affected = trusts.filter((t) => {
    // Only check external trusts (not forest or intra-forest)
    const isExternal =
      (t.trustAttributes & TRUST_ATTRIBUTE_FOREST_TRANSITIVE) === 0 &&
      (t.trustAttributes & TRUST_ATTRIBUTE_WITHIN_FOREST) === 0;

    if (!isExternal) return false;

    // Check if selective authentication is disabled
    const selectiveAuthDisabled = (t.trustAttributes & TRUST_ATTRIBUTE_CROSS_ORGANIZATION) === 0;

    return selectiveAuthDisabled;
  });

  return {
    type: 'TRUST_EXTERNAL_NO_SELECTIVE_AUTH',
    severity: 'high',
    category: 'trusts',
    title: 'External Trust Without Selective Authentication',
    description:
      'External trust without selective authentication allows any user from the trusted domain to authenticate to any resource in this domain.',
    count: affected.length,
    affectedEntities: includeDetails ? affected.map((t) => t.name) : undefined,
    details:
      affected.length > 0
        ? {
            recommendation:
              'Enable selective authentication and explicitly grant access only to required resources.',
          }
        : undefined,
  };
}

/**
 * TRUST_BIDIRECTIONAL: Two-way trust relationship
 * Increases attack surface - compromise in either domain affects both
 */
export function detectTrustBidirectional(
  trusts: ADTrustExtended[],
  includeDetails: boolean
): Finding {
  const affected = trusts.filter((t) => {
    // Skip intra-forest trusts (parent-child are always bidirectional by design)
    if ((t.trustAttributes & TRUST_ATTRIBUTE_WITHIN_FOREST) !== 0) {
      return false;
    }

    return t.trustDirection === TRUST_DIRECTION_BIDIRECTIONAL;
  });

  return {
    type: 'TRUST_BIDIRECTIONAL',
    severity: 'medium',
    category: 'trusts',
    title: 'Bidirectional Trust Relationship',
    description:
      'Two-way trust allows authentication in both directions, increasing the attack surface. A compromise in either domain can lead to lateral movement to the other.',
    count: affected.length,
    affectedEntities: includeDetails ? affected.map((t) => t.name) : undefined,
    details:
      affected.length > 0
        ? {
            recommendation:
              'Consider using one-way trusts where possible. Implement selective authentication.',
          }
        : undefined,
  };
}

/**
 * TRUST_FOREST_TRANSITIVE: Transitive forest trust
 * Trust extends to all domains in the trusted forest
 */
export function detectTrustForestTransitive(
  trusts: ADTrustExtended[],
  includeDetails: boolean
): Finding {
  const affected = trusts.filter((t) => {
    return (t.trustAttributes & TRUST_ATTRIBUTE_FOREST_TRANSITIVE) !== 0;
  });

  return {
    type: 'TRUST_FOREST_TRANSITIVE',
    severity: 'medium',
    category: 'trusts',
    title: 'Transitive Forest Trust',
    description:
      'Forest trust is transitive, meaning all domains in the trusted forest can access this domain. This significantly increases the trust boundary.',
    count: affected.length,
    affectedEntities: includeDetails ? affected.map((t) => t.name) : undefined,
    details:
      affected.length > 0
        ? {
            recommendation:
              'Review necessity of forest trust. Consider selective authentication and SID filtering.',
          }
        : undefined,
  };
}

// Encryption type bit flags from msDS-SupportedEncryptionTypes
const ENC_TYPE_DES_CBC_CRC = 0x1;
const ENC_TYPE_DES_CBC_MD5 = 0x2;
const ENC_TYPE_RC4_HMAC = 0x4;
const ENC_TYPE_AES128 = 0x8;
const ENC_TYPE_AES256 = 0x10;
const ENC_WEAK_ONLY = ENC_TYPE_DES_CBC_CRC | ENC_TYPE_DES_CBC_MD5 | ENC_TYPE_RC4_HMAC;
const ENC_AES_TYPES = ENC_TYPE_AES128 | ENC_TYPE_AES256;

/**
 * TRUST_AES_DISABLED: AES encryption not enabled on trust
 * Forces use of weaker encryption algorithms
 */
export function detectTrustAesDisabled(
  trusts: ADTrustExtended[],
  includeDetails: boolean
): Finding {
  const affected = trusts.filter((t) => {
    // Skip if encryption types not available
    if (t.supportedEncryptionTypes === undefined) return false;
    // Check if AES is NOT supported (neither AES128 nor AES256)
    return (t.supportedEncryptionTypes & ENC_AES_TYPES) === 0;
  });

  return {
    type: 'TRUST_AES_DISABLED',
    severity: 'high',
    category: 'trusts',
    title: 'AES Encryption Disabled on Trust',
    description:
      'Trust relationship does not support AES encryption. This forces the use of weaker encryption algorithms (RC4/DES) which are more vulnerable to offline cracking.',
    count: affected.length,
    affectedEntities: includeDetails ? affected.map((t) => t.name) : undefined,
    details:
      affected.length > 0
        ? {
            recommendation:
              'Enable AES128 and AES256 encryption on trust relationship. Ensure both domains support AES.',
          }
        : undefined,
  };
}

/**
 * TRUST_RC4_ONLY: Trust only supports RC4 encryption
 * RC4 is deprecated and vulnerable to offline attacks
 */
export function detectTrustRc4Only(
  trusts: ADTrustExtended[],
  includeDetails: boolean
): Finding {
  const affected = trusts.filter((t) => {
    // Skip if encryption types not available
    if (t.supportedEncryptionTypes === undefined) return false;
    // Check if ONLY weak encryption is supported (RC4/DES only, no AES)
    const hasOnlyWeak =
      (t.supportedEncryptionTypes & ENC_WEAK_ONLY) !== 0 &&
      (t.supportedEncryptionTypes & ENC_AES_TYPES) === 0;
    // Specifically RC4 only (not DES)
    const isRc4Only =
      hasOnlyWeak && (t.supportedEncryptionTypes & ENC_TYPE_RC4_HMAC) !== 0;
    return isRc4Only;
  });

  return {
    type: 'TRUST_RC4_ONLY',
    severity: 'high',
    category: 'trusts',
    title: 'Trust Only Supports RC4 Encryption',
    description:
      'Trust relationship only supports RC4 encryption (no AES). RC4 is deprecated and Kerberos tickets encrypted with RC4 are vulnerable to offline cracking attacks.',
    count: affected.length,
    affectedEntities: includeDetails ? affected.map((t) => t.name) : undefined,
    details:
      affected.length > 0
        ? {
            recommendation:
              'Enable AES encryption on trust. If the partner domain does not support AES, plan an upgrade path.',
          }
        : undefined,
  };
}

/**
 * TRUST_INACTIVE: Trust not modified in 180+ days
 * May indicate abandoned or forgotten trust relationships
 */
export function detectTrustInactive(
  trusts: ADTrustExtended[],
  includeDetails: boolean
): Finding {
  const now = Date.now();
  const sixMonthsAgo = now - 180 * 24 * 60 * 60 * 1000;

  const affected = trusts.filter((t) => {
    // Skip if whenChanged not available
    if (!t.whenChanged) return false;
    // Check if trust hasn't been modified in 180+ days
    return t.whenChanged.getTime() < sixMonthsAgo;
  });

  return {
    type: 'TRUST_INACTIVE',
    severity: 'medium',
    category: 'trusts',
    title: 'Inactive Trust Relationship',
    description:
      'Trust relationship has not been modified in over 180 days. May indicate an abandoned or forgotten trust that should be reviewed for necessity.',
    count: affected.length,
    affectedEntities: includeDetails ? affected.map((t) => t.name) : undefined,
    details:
      affected.length > 0
        ? {
            recommendation:
              'Review necessity of inactive trusts. Remove trusts that are no longer needed to reduce attack surface.',
          }
        : undefined,
  };
}

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
