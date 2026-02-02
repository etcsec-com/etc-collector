/**
 * ACL_DS_REPLICATION_GET_CHANGES - DCSync capability
 */

import { AclEntry } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';
import { getUniqueObjects } from '../utils';

/**
 * Detect DS-Replication-Get-Changes rights (DCSync capability)
 *
 * These rights allow extracting password hashes from the domain.
 *
 * @param aclEntries - Array of ACL entries
 * @param includeDetails - Whether to include affected entity details
 * @returns Finding for ACL_DS_REPLICATION_GET_CHANGES
 */
export function detectAclDsReplicationGetChanges(
  aclEntries: AclEntry[],
  includeDetails: boolean
): Finding {
  // DS-Replication-Get-Changes: 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2
  // DS-Replication-Get-Changes-All: 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2
  const REPLICATION_GUIDS = [
    '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2',
    '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2',
  ];

  const affected = aclEntries.filter((ace) => {
    return (
      ace.objectType && REPLICATION_GUIDS.includes(ace.objectType.toLowerCase())
    );
  });

  const uniqueObjects = getUniqueObjects(affected);
  const totalInstances = affected.length;

  return {
    type: 'ACL_DS_REPLICATION_GET_CHANGES',
    severity: 'critical',
    category: 'permissions',
    title: 'DS-Replication-Get-Changes Rights (DCSync)',
    description:
      'Non-standard principals with directory replication rights. ' +
      'Enables DCSync attacks to extract all password hashes from the domain.',
    count: uniqueObjects.length,
    totalInstances: totalInstances !== uniqueObjects.length ? totalInstances : undefined,
    affectedEntities: includeDetails ? uniqueObjects : undefined,
    details: {
      risk: 'Complete domain compromise through password hash extraction.',
      recommendation: 'Remove replication rights from all non-DC accounts.',
    },
  };
}
