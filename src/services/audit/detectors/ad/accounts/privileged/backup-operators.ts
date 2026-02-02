/**
 * Backup Operators Membership Detector
 * Check for Backup Operators membership
 */

import { ADUser } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';
import { toAffectedUserEntities } from '../../../../../../utils/entity-converter';

export function detectBackupOperatorsMember(users: ADUser[], includeDetails: boolean): Finding {
  const affected = users.filter((u) => {
    if (!u.memberOf) return false;
    return u.memberOf.some((dn) => dn.includes('CN=Backup Operators'));
  });

  return {
    type: 'BACKUP_OPERATORS_MEMBER',
    severity: 'high',
    category: 'accounts',
    title: 'Backup Operators Member',
    description: 'Users in Backup Operators group. Can backup/restore files and bypass ACLs.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected) : undefined,
  };
}
