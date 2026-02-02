/**
 * TRUST_BIDIRECTIONAL Detector
 * Two-way trust relationship - increases attack surface, compromise in either domain affects both
 */

import { Finding } from '../../../../../types/finding.types';
import {
  ADTrustExtended,
  TRUST_ATTRIBUTE_WITHIN_FOREST,
  TRUST_DIRECTION_BIDIRECTIONAL,
} from '../../../../../types/trust.types';

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
