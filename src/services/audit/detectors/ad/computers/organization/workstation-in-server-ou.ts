/**
 * Workstation in Server OU Detector
 * Detect workstations in server OUs
 * Workstations should be in workstation OUs, not server OUs
 */

import { ADComputer } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';
import { toAffectedComputerEntities, ldapAttrToString } from '../../../../../../utils/entity-converter';

export function detectWorkstationInServerOu(computers: ADComputer[], includeDetails: boolean): Finding {
  const serverOuPatterns = [/ou=servers/i, /ou=server/i, /ou=datacenter/i, /ou=production/i];
  const workstationOsPatterns = [/windows 10/i, /windows 11/i, /windows 7/i, /windows 8/i];
  const workstationNamePatterns = [/^ws/i, /^pc/i, /^laptop/i, /^desktop/i, /^nb/i];

  const affected = computers.filter((c) => {
    // Check if it's in a server OU
    const isInServerOU = serverOuPatterns.some((p) => p.test(c.dn));
    if (!isInServerOU) return false;

    // Check if it's actually a workstation (not a server)
    const os = ldapAttrToString(c.operatingSystem);
    const isWorkstation =
      workstationNamePatterns.some((p) => p.test(c.sAMAccountName || '')) ||
      (os && workstationOsPatterns.some((p) => p.test(os)));

    return isWorkstation;
  });

  return {
    type: 'WORKSTATION_IN_SERVER_OU',
    severity: 'low',
    category: 'computers',
    title: 'Workstation in Server OU',
    description:
      'Workstation computers found in server OUs. This causes incorrect GPO application and may indicate organizational issues.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedComputerEntities(affected) : undefined,
    details:
      affected.length > 0
        ? {
            recommendation: 'Move workstations to appropriate workstation OUs for proper GPO targeting.',
            impact: 'Server-targeted GPOs may apply to workstations causing configuration issues.',
          }
        : undefined,
  };
}
