/**
 * ACL_ADD_MEMBER - Add-Member rights on groups
 */

import { AclEntry } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';
import { getUniqueObjects } from '../utils';

/**
 * Detect Add-Member rights on groups
 *
 * Add-Member allows adding arbitrary users to groups.
 *
 * @param aclEntries - Array of ACL entries
 * @param includeDetails - Whether to include affected entity details
 * @returns Finding for ACL_ADD_MEMBER
 */
export function detectAclAddMember(aclEntries: AclEntry[], includeDetails: boolean): Finding {
  // Member attribute GUID: bf9679c0-0de6-11d0-a285-00aa003049e2
  const MEMBER_GUID = 'bf9679c0-0de6-11d0-a285-00aa003049e2';
  const WRITE_PROPERTY = 0x20;

  const affected = aclEntries.filter((ace) => {
    const hasWriteProperty = (ace.accessMask & WRITE_PROPERTY) !== 0;
    const isMemberProperty = ace.objectType?.toLowerCase() === MEMBER_GUID;
    return hasWriteProperty && isMemberProperty;
  });

  const uniqueObjects = getUniqueObjects(affected);
  const totalInstances = affected.length;

  return {
    type: 'ACL_ADD_MEMBER',
    severity: 'medium',
    category: 'permissions',
    title: 'Add-Member Rights on Groups',
    description:
      'Principals with rights to add members to groups. ' +
      'Can be abused to add accounts to privileged groups.',
    count: uniqueObjects.length,
    totalInstances: totalInstances !== uniqueObjects.length ? totalInstances : undefined,
    affectedEntities: includeDetails ? uniqueObjects : undefined,
  };
}
