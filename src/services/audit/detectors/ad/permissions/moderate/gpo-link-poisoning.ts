/**
 * GPO_LINK_POISONING - Weak ACLs on Group Policy Objects
 */

import { AclEntry } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';
import { getUniqueObjects } from '../utils';

/**
 * Check for weak ACLs on Group Policy Objects
 */
export function detectGpoLinkPoisoning(aclEntries: AclEntry[], includeDetails: boolean): Finding {
  const GENERIC_WRITE = 0x40000000;
  const GENERIC_ALL = 0x10000000;
  const WRITE_DACL = 0x00040000;

  const affected = aclEntries.filter((ace) => {
    const isGpo = ace.objectDn.includes('CN=Policies,CN=System');
    const hasDangerousPermission =
      (ace.accessMask & GENERIC_ALL) !== 0 ||
      (ace.accessMask & GENERIC_WRITE) !== 0 ||
      (ace.accessMask & WRITE_DACL) !== 0;

    return isGpo && hasDangerousPermission;
  });

  const uniqueObjects = getUniqueObjects(affected);
  const totalInstances = affected.length;

  return {
    type: 'GPO_LINK_POISONING',
    severity: 'medium',
    category: 'permissions',
    title: 'GPO Link Poisoning',
    description: 'Weak ACLs on Group Policy Objects. Can modify GPO to execute code on targeted systems.',
    count: uniqueObjects.length,
    totalInstances: totalInstances !== uniqueObjects.length ? totalInstances : undefined,
    affectedEntities: includeDetails ? uniqueObjects : undefined,
  };
}
