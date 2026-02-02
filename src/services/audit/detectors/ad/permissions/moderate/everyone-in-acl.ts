/**
 * EVERYONE_IN_ACL - Everyone/Authenticated Users with write permissions
 */

import { AclEntry } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';
import { getUniqueObjects } from '../utils';

/**
 * Check for Everyone/Authenticated Users with write permissions
 */
export function detectEveryoneInAcl(aclEntries: AclEntry[], includeDetails: boolean): Finding {
  const EVERYONE_SID = 'S-1-1-0';
  const AUTHENTICATED_USERS_SID = 'S-1-5-11';
  const WRITE_MASK = 0x00020000; // ADS_RIGHT_DS_WRITE_PROP

  const affected = aclEntries.filter((ace) => {
    const isEveryone = ace.trustee === EVERYONE_SID || ace.trustee === AUTHENTICATED_USERS_SID;
    const hasWrite = (ace.accessMask & WRITE_MASK) !== 0;
    return isEveryone && hasWrite;
  });

  const uniqueObjects = getUniqueObjects(affected);
  const totalInstances = affected.length;

  return {
    type: 'EVERYONE_IN_ACL',
    severity: 'medium',
    category: 'permissions',
    title: 'Everyone in ACL',
    description: 'Everyone or Authenticated Users with write permissions in ACL. Overly permissive access.',
    count: uniqueObjects.length,
    totalInstances: totalInstances !== uniqueObjects.length ? totalInstances : undefined,
    affectedEntities: includeDetails ? uniqueObjects : undefined,
  };
}
