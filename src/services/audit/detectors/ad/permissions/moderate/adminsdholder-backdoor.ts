/**
 * ADMINSDHOLDER_BACKDOOR - Unexpected ACL on AdminSDHolder object
 */

import { AclEntry } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';
import { getUniqueObjects } from '../utils';

/**
 * Check for unexpected ACL on AdminSDHolder object
 */
export function detectAdminSdHolderBackdoor(aclEntries: AclEntry[], includeDetails: boolean): Finding {
  const affected = aclEntries.filter((ace) => {
    return ace.objectDn.includes('CN=AdminSDHolder,CN=System');
  });

  const uniqueObjects = getUniqueObjects(affected);
  const totalInstances = affected.length;

  return {
    type: 'ADMINSDHOLDER_BACKDOOR',
    severity: 'medium',
    category: 'permissions',
    title: 'AdminSDHolder Backdoor',
    description: 'Unexpected ACL on AdminSDHolder object. Persistent permissions on admin accounts.',
    count: uniqueObjects.length,
    totalInstances: totalInstances !== uniqueObjects.length ? totalInstances : undefined,
    affectedEntities: includeDetails ? uniqueObjects : undefined,
  };
}
