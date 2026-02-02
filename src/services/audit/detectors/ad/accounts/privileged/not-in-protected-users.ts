/**
 * Not in Protected Users Detector
 * Check for privileged accounts not in Protected Users group
 */

import { ADUser } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';
import { toAffectedUserEntities } from '../../../../../../utils/entity-converter';

export function detectNotInProtectedUsers(users: ADUser[], includeDetails: boolean): Finding {
  const privilegedGroups = ['Domain Admins', 'Enterprise Admins', 'Schema Admins'];

  const affected = users.filter((u) => {
    if (!u.memberOf) return false;
    const isPrivileged = u.memberOf.some((dn) =>
      privilegedGroups.some((group) => dn.includes(`CN=${group}`))
    );
    const isInProtectedUsers = u.memberOf.some((dn) => dn.includes('CN=Protected Users'));
    return isPrivileged && !isInProtectedUsers;
  });

  return {
    type: 'NOT_IN_PROTECTED_USERS',
    severity: 'high',
    category: 'accounts',
    title: 'Not in Protected Users Group',
    description: 'Privileged accounts not in Protected Users group. Missing additional security protections.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected) : undefined,
  };
}
