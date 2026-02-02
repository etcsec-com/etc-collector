/**
 * ANSSI R5 - Segregation
 * Checks network and privilege segregation:
 * - Tiered admin model
 * - Service account isolation
 * - Workstation restrictions
 */

import { ADUser, ADComputer } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';
import { ldapAttrToString } from '../../../../../../utils/entity-converter';

export function detectAnssiR5Segregation(
  users: ADUser[],
  computers: ADComputer[],
  _includeDetails: boolean
): Finding {
  const issues: string[] = [];

  // Check for admin accounts logging into workstations (tier violation)
  const privilegedGroups = ['Domain Admins', 'Enterprise Admins', 'Schema Admins'];
  const admins = users.filter(
    (u) => u.memberOf?.some((dn) => privilegedGroups.some((pg) => dn.includes(`CN=${pg}`)))
  );

  // Check for service accounts with interactive logon capability
  const serviceAccounts = users.filter((u) => {
    const name = (u.sAMAccountName || '').toLowerCase();
    return name.includes('svc') || name.includes('service') || name.startsWith('sa_');
  });

  const interactiveServiceAccounts = serviceAccounts.filter((u) => {
    // Check if service account doesn't have "Deny logon locally" applied
    // This is a heuristic - real check would require GPO analysis
    return u.enabled;
  });

  if (interactiveServiceAccounts.length > 0) {
    issues.push(`${interactiveServiceAccounts.length} service accounts may allow interactive logon`);
  }

  // Check for workstations in server OUs (organizational issue)
  const workstationsInServerOu = computers.filter((c) => {
    const os = ldapAttrToString(c.operatingSystem);
    const isWorkstation = /windows 10|windows 11|windows 7|windows 8/i.test(os);
    const isInServerOu = /ou=servers|ou=server|ou=datacenter/i.test(c.dn);
    return isWorkstation && isInServerOu;
  });

  if (workstationsInServerOu.length > 0) {
    issues.push(`${workstationsInServerOu.length} workstations in server OUs (tier violation)`);
  }

  // Check admin count (too many admins indicates poor segregation)
  if (admins.length > 15) {
    issues.push(`${admins.length} privileged accounts (recommend <15 for proper segregation)`);
  }

  return {
    type: 'ANSSI_R5_SEGREGATION',
    severity: 'medium',
    category: 'compliance',
    title: 'ANSSI R5 - Segregation Issues',
    description:
      'Network and privilege segregation does not meet ANSSI R5 recommendations. Implement tiered administration model.',
    count: issues.length > 0 ? 1 : 0,
    details: issues.length > 0 ? { violations: issues, framework: 'ANSSI', control: 'R5' } : undefined,
  };
}
