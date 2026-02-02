/**
 * Computer ACL Abuse Detector
 * Check for computer with ACL abuse potential
 */

import { ADComputer } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';
import { toAffectedComputerEntities } from '../../../../../../utils/entity-converter';

export function detectComputerAclAbuse(computers: ADComputer[], includeDetails: boolean): Finding {
  // Note: This requires ACL analysis which would be done in permissions detector
  // For now, we detect computers with suspicious ACL attributes
  const affected = computers.filter((c) => {
    return 'dangerousAcl' in c && (c as any).dangerousAcl;
  });

  return {
    type: 'COMPUTER_ACL_ABUSE',
    severity: 'high',
    category: 'computers',
    title: 'Computer ACL Abuse',
    description: 'Computer with dangerous ACL permissions. Can modify computer object properties and escalate privileges.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedComputerEntities(affected) : undefined,
  };
}
