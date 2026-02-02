/**
 * ACL_WRITEDACL - WriteDACL permission on sensitive objects
 */

import { AclEntry } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';
import { getUniqueObjects } from '../utils';

/**
 * Check for WriteDACL permission on sensitive objects
 */
export function detectAclWriteDacl(aclEntries: AclEntry[], includeDetails: boolean): Finding {
  const WRITE_DACL = 0x00040000;

  const affected = aclEntries.filter((ace) => {
    return (ace.accessMask & WRITE_DACL) !== 0;
  });

  const uniqueObjects = getUniqueObjects(affected);
  const totalInstances = affected.length;

  return {
    type: 'ACL_WRITEDACL',
    severity: 'high',
    category: 'permissions',
    title: 'ACL WriteDACL',
    description: "WriteDACL permission on sensitive AD objects. Can modify object's security descriptor to grant additional permissions.",
    count: uniqueObjects.length,
    totalInstances: totalInstances !== uniqueObjects.length ? totalInstances : undefined,
    affectedEntities: includeDetails ? uniqueObjects : undefined,
  };
}
