/**
 * MFA_NOT_ENFORCED - Privileged accounts without MFA
 * Frameworks: PCI-DSS 8.3, SOC2 CC6.1, ISO27001 A.9.4.2
 * Checks if privileged accounts require smartcard/MFA
 */

import { ADUser } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';
import { toAffectedUserEntities } from '../../../../../../utils/entity-converter';

export function detectMfaNotEnforced(
  users: ADUser[],
  includeDetails: boolean
): Finding {
  const privilegedGroups = ['Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators'];

  const privilegedUsers = users.filter((u) => {
    if (!u.memberOf) return false;
    return u.memberOf.some((dn) => privilegedGroups.some((pg) => dn.includes(`CN=${pg}`)));
  });

  // Check for privileged users without SMARTCARD_REQUIRED flag
  const noMfa = privilegedUsers.filter((u) => {
    const uac = u.userAccountControl || 0;
    return (uac & 0x40000) === 0; // SMARTCARD_REQUIRED not set
  });

  return {
    type: 'MFA_NOT_ENFORCED',
    severity: 'high',
    category: 'compliance',
    title: 'MFA Not Enforced for Privileged Accounts',
    description:
      'Privileged accounts do not require multi-factor authentication (smartcard). Required by PCI-DSS 8.3, SOC2 CC6.1, ISO27001 A.9.4.2.',
    count: noMfa.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(noMfa.slice(0, 50)) : undefined,
    details: noMfa.length > 0 ? {
      frameworks: ['PCI-DSS', 'SOC2', 'ISO27001'],
      controls: ['8.3', 'CC6.1', 'A.9.4.2'],
      recommendation: 'Enable smartcard requirement for all privileged accounts',
    } : undefined,
  };
}
