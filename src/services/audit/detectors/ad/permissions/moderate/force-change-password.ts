/**
 * ACL_FORCECHANGEPASSWORD - ForceChangePassword extended right
 */

import { AclEntry } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';
import { getUniqueObjects } from '../utils';

/**
 * Check for ForceChangePassword extended right
 */
export function detectAclForceChangePassword(aclEntries: AclEntry[], includeDetails: boolean): Finding {
  const FORCE_CHANGE_PASSWORD_GUID = '00299570-246d-11d0-a768-00aa006e0529';

  const affected = aclEntries.filter((ace) => {
    return ace.objectType === FORCE_CHANGE_PASSWORD_GUID;
  });

  const uniqueObjects = getUniqueObjects(affected);
  const totalInstances = affected.length;

  return {
    type: 'ACL_FORCECHANGEPASSWORD',
    severity: 'medium',
    category: 'permissions',
    title: 'ACL Force Change Password',
    description: 'ExtendedRight to force password change on user accounts. Can reset passwords without knowing current password.',
    count: uniqueObjects.length,
    totalInstances: totalInstances !== uniqueObjects.length ? totalInstances : undefined,
    affectedEntities: includeDetails ? uniqueObjects : undefined,
  };
}

/**
 * Detect User-Force-Change-Password rights
 *
 * This right allows resetting user passwords without knowing the current password.
 *
 * @param aclEntries - Array of ACL entries
 * @param includeDetails - Whether to include affected entity details
 * @returns Finding for ACL_USER_FORCE_CHANGE_PASSWORD
 */
export function detectAclUserForceChangePassword(
  aclEntries: AclEntry[],
  includeDetails: boolean
): Finding {
  // User-Force-Change-Password: 00299570-246d-11d0-a768-00aa006e0529
  const FORCE_CHANGE_PASSWORD_GUID = '00299570-246d-11d0-a768-00aa006e0529';

  const affected = aclEntries.filter((ace) => {
    return ace.objectType?.toLowerCase() === FORCE_CHANGE_PASSWORD_GUID;
  });

  const uniqueObjects = getUniqueObjects(affected);
  const totalInstances = affected.length;

  return {
    type: 'ACL_USER_FORCE_CHANGE_PASSWORD',
    severity: 'medium',
    category: 'permissions',
    title: 'User-Force-Change-Password Rights',
    description:
      'Principals with rights to force password change on user accounts. ' +
      'Can reset passwords to take over accounts.',
    count: uniqueObjects.length,
    totalInstances: totalInstances !== uniqueObjects.length ? totalInstances : undefined,
    affectedEntities: includeDetails ? uniqueObjects : undefined,
  };
}
