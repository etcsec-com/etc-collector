/**
 * Sensitive Delegation Detector
 * Check for sensitive accounts with unconstrained delegation
 */

import { ADUser } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';
import { toAffectedUserEntities } from '../../../../../../utils/entity-converter';

export function detectSensitiveDelegation(users: ADUser[], includeDetails: boolean): Finding {
  const privilegedGroups = [
    'Domain Admins',
    'Enterprise Admins',
    'Schema Admins',
    'Administrators',
  ];

  const affected = users.filter((u) => {
    if (!u.userAccountControl || !u.memberOf) return false;
    const hasUnconstrainedDeleg = (u.userAccountControl & 0x80000) !== 0;
    const isPrivileged = u.memberOf.some((dn) =>
      privilegedGroups.some((group) => dn.includes(`CN=${group}`))
    );
    return hasUnconstrainedDeleg && isPrivileged;
  });

  return {
    type: 'SENSITIVE_DELEGATION',
    severity: 'critical',
    category: 'accounts',
    title: 'Sensitive Account with Delegation',
    description: 'Privileged accounts (Domain/Enterprise Admins) with unconstrained delegation. Extreme security risk.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected) : undefined,
  };
}
