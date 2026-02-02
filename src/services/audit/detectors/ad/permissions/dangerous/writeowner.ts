/**
 * ACL_WRITEOWNER - WriteOwner permission on sensitive objects
 */

import { AclEntry } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';
import { getUniqueObjects } from '../utils';

/**
 * Check for WriteOwner permission on sensitive objects
 */
export function detectAclWriteOwner(aclEntries: AclEntry[], includeDetails: boolean): Finding {
  const WRITE_OWNER = 0x00080000;

  const affected = aclEntries.filter((ace) => {
    return (ace.accessMask & WRITE_OWNER) !== 0;
  });

  const uniqueObjects = getUniqueObjects(affected);
  const totalInstances = affected.length;

  return {
    type: 'ACL_WRITEOWNER',
    severity: 'high',
    category: 'permissions',
    title: 'ACL WriteOwner',
    description: 'WriteOwner permission on sensitive AD objects. Can take ownership of object and modify permissions.',
    count: uniqueObjects.length,
    totalInstances: totalInstances !== uniqueObjects.length ? totalInstances : undefined,
    affectedEntities: includeDetails ? uniqueObjects : undefined,
  };
}
