/**
 * BUILTIN_MODIFIED - Builtin groups with non-standard members
 */

import { ADGroup } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';
import { toAffectedADGroupEntities } from '../../../../../../utils/entity-converter';

/**
 * Detect builtin groups with non-standard members
 * Builtin groups should only contain expected system accounts
 */
export function detectBuiltinModified(groups: ADGroup[], includeDetails: boolean): Finding {
  // Builtin groups and their expected default members
  const builtinDefaults: { [key: string]: string[] } = {
    Administrators: ['Administrator', 'Domain Admins', 'Enterprise Admins'],
    Users: ['Domain Users', 'Authenticated Users', 'INTERACTIVE'],
    Guests: ['Guest', 'Domain Guests'],
    'Remote Desktop Users': [],
    'Network Configuration Operators': [],
    'Performance Monitor Users': [],
    'Performance Log Users': [],
    'Distributed COM Users': [],
    'IIS_IUSRS': [],
    'Cryptographic Operators': [],
    'Event Log Readers': [],
    'Certificate Service DCOM Access': [],
  };

  const affected = groups.filter((g) => {
    const name = g.sAMAccountName || '';

    // Check if it's a builtin group we monitor
    if (!builtinDefaults[name]) return false;

    const expectedMembers = builtinDefaults[name];
    const actualMembers = g.member ?? [];

    // Check for unexpected members
    const hasUnexpectedMembers = actualMembers.some((memberDn) => {
      const memberCn = memberDn.match(/CN=([^,]+)/i)?.[1] || '';
      // Check if this member is in the expected list
      return !expectedMembers.some((exp) => memberCn.toLowerCase().includes(exp.toLowerCase()));
    });

    return hasUnexpectedMembers;
  });

  return {
    type: 'BUILTIN_MODIFIED',
    severity: 'high',
    category: 'groups',
    title: 'Builtin Group Modified',
    description:
      'Builtin groups contain non-standard members. This may indicate privilege escalation or backdoor access.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedADGroupEntities(affected) : undefined,
    details:
      affected.length > 0
        ? {
            groups: affected.map((g) => g.sAMAccountName || g.dn),
            recommendation:
              'Review membership of builtin groups and remove unexpected members. Document any intentional additions.',
            risk: 'Attackers often add accounts to builtin groups for persistent access.',
          }
        : undefined,
  };
}
