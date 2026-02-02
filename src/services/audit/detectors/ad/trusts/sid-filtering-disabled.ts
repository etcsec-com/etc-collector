/**
 * TRUST_SID_FILTERING_DISABLED Detector
 * SID filtering not enabled - allows SID history injection attacks across trust boundary
 */

import { Finding } from '../../../../../types/finding.types';
import {
  ADTrustExtended,
  TRUST_ATTRIBUTE_QUARANTINED_DOMAIN,
  TRUST_ATTRIBUTE_WITHIN_FOREST,
} from '../../../../../types/trust.types';

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
