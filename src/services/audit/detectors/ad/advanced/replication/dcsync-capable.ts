/**
 * DCSync Capable Detector
 * Check for DCSync capable accounts
 */

import { ADUser } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';
import { toAffectedUserEntities } from '../../../../../../utils/entity-converter';

export function detectDcsyncCapable(users: ADUser[], includeDetails: boolean): Finding {
  const affected = users.filter((u) => {
    return (u as any).hasDcsyncRights; // This would be populated by ACL analysis
  });

  return {
    type: 'DCSYNC_CAPABLE',
    severity: 'high',
    category: 'advanced',
    title: 'DCSync Capable',
    description: 'Account with DS-Replication-Get-Changes and DS-Replication-Get-Changes-All rights. Can extract all password hashes.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected) : undefined,
  };
}
