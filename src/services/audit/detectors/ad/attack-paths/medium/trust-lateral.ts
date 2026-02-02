/**
 * Trust Lateral Movement Path Detector
 *
 * Detects trust relationships enabling lateral movement.
 * Trusts without SID filtering or with bidirectional access.
 */

import { Finding } from '../../../../../../types/finding.types';
import { ADTrustExtended } from '../../../../../../types/trust.types';

/**
 * Detect trust relationships enabling lateral movement
 * Trusts without SID filtering or with bidirectional access
 */
export function detectPathTrustLateral(trusts: ADTrustExtended[], includeDetails: boolean): Finding {
  const riskyTrusts = trusts.filter((t) => {
    // SID filtering disabled = can inject SIDs from trusted domain
    const noSidFiltering = !t.sidFilteringEnabled;
    // Bidirectional = both domains can authenticate to each other
    const bidirectional = t.trustDirection === 3 || t.direction === 'bidirectional';
    // Forest trust without selective auth
    const forestNoSelectiveAuth = t.type === 'forest' && !t.selectiveAuthEnabled;

    return noSidFiltering || (bidirectional && forestNoSelectiveAuth);
  });

  return {
    type: 'PATH_TRUST_LATERAL',
    severity: 'high',
    category: 'attack-paths',
    title: 'Trust Relationship Enables Lateral Movement',
    description:
      'Domain trusts configured without proper security controls (SID filtering, selective authentication). Compromising trusted domain can lead to this domain.',
    count: riskyTrusts.length,
    affectedEntities: includeDetails ? riskyTrusts.map((t) => t.name) : undefined,
    details:
      riskyTrusts.length > 0
        ? {
            totalTrusts: trusts.length,
            riskyTrusts: riskyTrusts.map((t) => ({
              name: t.name,
              direction: t.direction,
              type: t.type,
              sidFiltering: t.sidFilteringEnabled,
              selectiveAuth: t.selectiveAuthEnabled,
            })),
            attackVector: 'Compromise trusted domain → Exploit trust → Access this domain',
            mitigation: 'Enable SID filtering, use selective authentication for forest trusts',
          }
        : undefined,
  };
}
