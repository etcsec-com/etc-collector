/**
 * ACL_GENERICALL - GenericAll permission on sensitive objects
 */

import { AclEntry } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';
import { getUniqueObjects } from '../utils';

/**
 * Check for GenericAll permission on sensitive objects
 *
 * GENERIC_ALL can be stored as:
 * - 0x10000000 (raw GENERIC_ALL)
 * - 0x000F01FF (Full Control for AD objects - mapped rights)
 */
export function detectAclGenericAll(aclEntries: AclEntry[], includeDetails: boolean): Finding {
  // GENERIC_ALL raw value
  const GENERIC_ALL = 0x10000000;
  // Full control mask for AD objects (all specific AD rights + standard rights)
  // This is what GENERIC_ALL maps to when stored in AD ACLs
  const AD_FULL_CONTROL = 0x000f01ff;

  const affected = aclEntries.filter((ace) => {
    // Check for raw GENERIC_ALL
    if ((ace.accessMask & GENERIC_ALL) !== 0) return true;
    // Check for Full Control (GENERIC_ALL mapped to AD rights)
    // The mask 0x000F01FF includes: DELETE | READ_CONTROL | WRITE_DAC | WRITE_OWNER | all DS rights
    return (ace.accessMask & AD_FULL_CONTROL) === AD_FULL_CONTROL;
  });

  const uniqueObjects = getUniqueObjects(affected);
  const totalInstances = affected.length;

  return {
    type: 'ACL_GENERICALL',
    severity: 'high',
    category: 'permissions',
    title: 'ACL GenericAll',
    description: 'GenericAll permission on sensitive AD objects. Full control over object (reset passwords, modify groups, etc.).',
    count: uniqueObjects.length,
    totalInstances: totalInstances !== uniqueObjects.length ? totalInstances : undefined,
    affectedEntities: includeDetails ? uniqueObjects : undefined,
  };
}
