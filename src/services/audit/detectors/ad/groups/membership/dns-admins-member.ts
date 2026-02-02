/**
 * DNS_ADMINS_MEMBER - DnsAdmins membership
 */

import { ADUser } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';
import { toAffectedUserEntities } from '../../../../../../utils/entity-converter';

/**
 * Check for DnsAdmins membership
 */
export function detectDnsAdminsMember(users: ADUser[], includeDetails: boolean): Finding {
  const affected = users.filter((u) => {
    if (!u.memberOf) return false;
    return u.memberOf.some((dn) => dn.includes('CN=DnsAdmins'));
  });

  return {
    type: 'DNS_ADMINS_MEMBER',
    severity: 'high',
    category: 'groups',
    title: 'DnsAdmins Member',
    description: 'Users in DnsAdmins group. Can load arbitrary DLLs on domain controllers (escalation to Domain Admin).',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected) : undefined,
  };
}
