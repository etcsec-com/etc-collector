/**
 * Exchange Privilege Escalation Path Detector
 * Detect Exchange privilege escalation paths
 *
 * Exchange security groups often have dangerous permissions that can be
 * abused for privilege escalation (WriteDacl on domain, etc.).
 */

import { ADUser } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';
import { toAffectedUserEntities } from '../../../../../../utils/entity-converter';

export function detectExchangePrivEscPath(
  users: ADUser[],
  includeDetails: boolean
): Finding {
  // Exchange groups with dangerous permissions
  const exchangeGroups = [
    'Exchange Trusted Subsystem',
    'Exchange Windows Permissions',
    'Organization Management',
    'Exchange Servers',
  ];

  // Find users in Exchange groups that might indicate privilege escalation risk
  const affected = users.filter((u) => {
    if (!u.enabled || !u.memberOf) return false;
    return u.memberOf.some((dn) =>
      exchangeGroups.some((eg) => dn.toLowerCase().includes(eg.toLowerCase()))
    );
  });

  return {
    type: 'EXCHANGE_PRIV_ESC_PATH',
    severity: 'critical',
    category: 'advanced',
    title: 'Exchange Privilege Escalation Risk',
    description:
      'Users in Exchange security groups with potentially dangerous permissions. ' +
      'Exchange Trusted Subsystem has WriteDacl on domain by default (CVE-2019-1166).',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected) : undefined,
    details: {
      exchangeGroups: exchangeGroups,
      recommendation:
        'Review Exchange group permissions on domain head. Apply PrivExchange mitigations.',
      reference: 'CVE-2019-1166, PrivExchange',
    },
  };
}
