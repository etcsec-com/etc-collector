/**
 * Computer in Admin Group Detector
 * Check for computer in admin groups
 */

import { ADComputer } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';
import { toAffectedComputerEntities } from '../../../../../../utils/entity-converter';

export function detectComputerInAdminGroup(computers: ADComputer[], includeDetails: boolean): Finding {
  const adminGroups = ['Domain Admins', 'Enterprise Admins'];

  const affected = computers.filter((c) => {
    const memberOf = (c as any).memberOf;
    if (!memberOf) return false;
    return memberOf.some((dn: string) => adminGroups.some((group) => dn.includes(`CN=${group}`)));
  });

  return {
    type: 'COMPUTER_IN_ADMIN_GROUP',
    severity: 'critical',
    category: 'computers',
    title: 'Computer in Admin Group',
    description: 'Computer account in Domain Admins or Enterprise Admins. Computer compromise leads to domain admin access.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedComputerEntities(affected) : undefined,
  };
}
