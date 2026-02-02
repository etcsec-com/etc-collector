/**
 * Computer Obsolete OS Detector
 * Check for computers running obsolete operating systems
 * Returns multiple findings, one per OS type detected
 */

import { ADComputer } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';
import { toAffectedComputerEntities, ldapAttrToString } from '../../../../../../utils/entity-converter';

/**
 * Obsolete OS patterns for detection
 */
export const OBSOLETE_OS_PATTERNS = [
  {
    pattern: /Windows XP/i,
    type: 'COMPUTER_OS_OBSOLETE_XP',
    severity: 'critical' as const,
    osName: 'Windows XP',
  },
  {
    pattern: /Server 2003/i,
    type: 'COMPUTER_OS_OBSOLETE_2003',
    severity: 'critical' as const,
    osName: 'Windows Server 2003',
  },
  {
    pattern: /Server 2008(?!\s*R2)/i, // 2008 but not 2008 R2
    type: 'COMPUTER_OS_OBSOLETE_2008',
    severity: 'high' as const,
    osName: 'Windows Server 2008',
  },
  {
    pattern: /Windows Vista/i,
    type: 'COMPUTER_OS_OBSOLETE_VISTA',
    severity: 'high' as const,
    osName: 'Windows Vista',
  },
];

export function detectComputerObsoleteOS(
  computers: ADComputer[],
  includeDetails: boolean
): Finding[] {
  return OBSOLETE_OS_PATTERNS.map(({ pattern, type, severity, osName }) => {
    const affected = computers.filter((c) => {
      const os = ldapAttrToString(c.operatingSystem);
      return os && pattern.test(os);
    });

    return {
      type,
      severity,
      category: 'computers' as const,
      title: `Obsolete OS: ${osName}`,
      description: `Computers running ${osName}, an unsupported operating system. No security patches available, making these systems highly vulnerable to exploitation.`,
      count: affected.length,
      affectedEntities: includeDetails ? toAffectedComputerEntities(affected) : undefined,
    };
  }).filter((f) => f.count > 0);
}
