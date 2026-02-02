/**
 * TRUST_FOREST_TRANSITIVE Detector
 * Transitive forest trust - trust extends to all domains in the trusted forest
 */

import { Finding } from '../../../../../types/finding.types';
import {
  ADTrustExtended,
  TRUST_ATTRIBUTE_FOREST_TRANSITIVE,
} from '../../../../../types/trust.types';

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
