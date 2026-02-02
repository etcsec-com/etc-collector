/**
 * Replica Directory Changes Detector
 * Detect accounts with directory replication rights (DCSync risk)
 *
 * Users with DS-Replication-Get-Changes and DS-Replication-Get-Changes-All
 * can perform DCSync attacks to extract password hashes.
 */

import { ADUser } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';
import { toAffectedUserEntities } from '../../../../../../utils/entity-converter';

export function detectReplicaDirectoryChanges(users: ADUser[], includeDetails: boolean): Finding {
  // This detection primarily works with ACL data, but we can check for
  // users in groups that typically have replication rights
  const replicationGroups = [
    'Domain Controllers',
    'Enterprise Domain Controllers',
    'Administrators',
    'Domain Admins',
    'Enterprise Admins',
  ];

  // Non-admin users that might have replication rights through delegation
  const affected = users.filter((u) => {
    if (!u.enabled || !u.memberOf) return false;
    // Check if user is in a group that shouldn't have replication rights
    // but description or other fields suggest replication permissions
    const rawDesc = (u as Record<string, unknown>)['description'];
    const description = typeof rawDesc === 'string' ? rawDesc : (Array.isArray(rawDesc) ? rawDesc[0] : '') || '';
    const hasReplicationHint =
      description.toLowerCase().includes('replication') ||
      description.toLowerCase().includes('dcsync') ||
      description.toLowerCase().includes('directory sync');

    // Check for non-standard accounts with admin count (may have been delegated)
    const isServiceLike = /^(svc|service|sync|repl)/i.test(u.sAMAccountName);
    const hasAdminCount = u.adminCount === 1;
    const isInReplicationGroup = u.memberOf.some((dn) =>
      replicationGroups.some((g) => dn.toLowerCase().includes(g.toLowerCase()))
    );

    return hasReplicationHint || (isServiceLike && hasAdminCount && !isInReplicationGroup);
  });

  return {
    type: 'REPLICA_DIRECTORY_CHANGES',
    severity: 'critical',
    category: 'accounts',
    title: 'Potential Directory Replication Rights',
    description:
      'Accounts that may have directory replication rights (DCSync capability). ' +
      'These accounts can extract all password hashes from the domain.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected) : undefined,
    details: {
      recommendation:
        'Review ACLs on domain head for DS-Replication-Get-Changes rights. Only Domain Controllers should have this permission.',
    },
  };
}
