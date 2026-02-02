/**
 * Computer Description Sensitive Detector
 * Check for computer description with sensitive data
 */

import { ADComputer } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';
import { toAffectedComputerEntities, ldapAttrToString } from '../../../../../../utils/entity-converter';

export function detectComputerDescriptionSensitive(computers: ADComputer[], includeDetails: boolean): Finding {
  const sensitivePatterns = [
    /password|passwd|pwd/i,
    /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/, // IP addresses
    /admin|root|sa/i,
  ];

  const affected = computers.filter((c) => {
    const rawDesc = (c as any).description;
    const description = ldapAttrToString(rawDesc);
    if (!description) return false;
    return sensitivePatterns.some((pattern) => pattern.test(description));
  });

  return {
    type: 'COMPUTER_DESCRIPTION_SENSITIVE',
    severity: 'medium',
    category: 'computers',
    title: 'Computer Description Sensitive',
    description: 'Computer description contains sensitive data (passwords, IPs, etc.). Information disclosure.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedComputerEntities(affected) : undefined,
  };
}
