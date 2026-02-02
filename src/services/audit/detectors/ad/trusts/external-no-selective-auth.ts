/**
 * TRUST_EXTERNAL_NO_SELECTIVE_AUTH Detector
 * External trust without selective authentication - all users from trusted domain can authenticate to any resource
 */

import { Finding } from '../../../../../types/finding.types';
import {
  ADTrustExtended,
  TRUST_ATTRIBUTE_CROSS_ORGANIZATION,
  TRUST_ATTRIBUTE_FOREST_TRANSITIVE,
  TRUST_ATTRIBUTE_WITHIN_FOREST,
} from '../../../../../types/trust.types';

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
