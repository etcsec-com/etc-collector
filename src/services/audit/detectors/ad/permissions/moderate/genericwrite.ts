/**
 * ACL_GENERICWRITE - GenericWrite permission on sensitive objects
 */

import { AclEntry } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';
import { getUniqueObjects } from '../utils';

/**
 * Check for GenericWrite permission on sensitive objects
 */
export function detectAclGenericWrite(aclEntries: AclEntry[], includeDetails: boolean): Finding {
  const GENERIC_WRITE = 0x40000000;

  const affected = aclEntries.filter((ace) => {
    return (ace.accessMask & GENERIC_WRITE) !== 0;
  });

  const uniqueObjects = getUniqueObjects(affected);
  const totalInstances = affected.length;

  return {
    type: 'ACL_GENERICWRITE',
    severity: 'medium',
    category: 'permissions',
    title: 'ACL GenericWrite',
    description: 'GenericWrite permission on sensitive AD objects. Can modify many object attributes.',
    count: uniqueObjects.length,
    totalInstances: totalInstances !== uniqueObjects.length ? totalInstances : undefined,
    affectedEntities: includeDetails ? uniqueObjects : undefined,
  };
}
