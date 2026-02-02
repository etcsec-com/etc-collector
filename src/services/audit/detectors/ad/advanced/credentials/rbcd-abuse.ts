/**
 * RBCD Abuse Detector
 * Check for RBCD abuse (Resource-Based Constrained Delegation)
 */

import { ADUser } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';
import { toAffectedUserEntities } from '../../../../../../utils/entity-converter';

export function detectRbcdAbuse(users: ADUser[], includeDetails: boolean): Finding {
  const affected = users.filter((u) => {
    const rbcdAttr = (u as any)['msDS-AllowedToActOnBehalfOfOtherIdentity'];
    // Check that attribute exists, is not null, not empty string, and not empty array
    return rbcdAttr && (Array.isArray(rbcdAttr) ? rbcdAttr.length > 0 : rbcdAttr !== '');
  });

  return {
    type: 'RBCD_ABUSE',
    severity: 'critical',
    category: 'advanced',
    title: 'RBCD Abuse',
    description: 'msDS-AllowedToActOnBehalfOfOtherIdentity configured. Enables privilege escalation via resource-based delegation.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected) : undefined,
  };
}
