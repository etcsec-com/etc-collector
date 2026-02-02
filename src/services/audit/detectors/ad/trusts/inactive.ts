/**
 * TRUST_INACTIVE Detector
 * Trust not modified in 180+ days - may indicate abandoned or forgotten trust relationships
 */

import { Finding } from '../../../../../types/finding.types';
import { ADTrustExtended } from '../../../../../types/trust.types';

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
