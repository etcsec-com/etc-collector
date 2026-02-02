/**
 * ACL_SELF_MEMBERSHIP - Self-membership rights on groups
 */

import { AclEntry } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';
import { getUniqueObjects } from '../utils';

/**
 * Detect Self-membership rights on groups
 *
 * Self-membership allows adding oneself to a group, enabling privilege escalation.
 *
 * @param aclEntries - Array of ACL entries
 * @param includeDetails - Whether to include affected entity details
 * @returns Finding for ACL_SELF_MEMBERSHIP
 */
export function detectAclSelfMembership(aclEntries: AclEntry[], includeDetails: boolean): Finding {
  // Self-membership GUID: bf9679c0-0de6-11d0-a285-00aa003049e2
  const SELF_MEMBERSHIP_GUID = 'bf9679c0-0de6-11d0-a285-00aa003049e2';
  const WRITE_SELF = 0x8; // ADS_RIGHT_DS_SELF

  const affected = aclEntries.filter((ace) => {
    const hasWriteSelf = (ace.accessMask & WRITE_SELF) !== 0;
    const isSelfMembership =
      ace.objectType?.toLowerCase() === SELF_MEMBERSHIP_GUID ||
      ace.objectType?.toLowerCase().includes('member');
    return hasWriteSelf || isSelfMembership;
  });

  const uniqueObjects = getUniqueObjects(affected);
  const totalInstances = affected.length;

  return {
    type: 'ACL_SELF_MEMBERSHIP',
    severity: 'high',
    category: 'permissions',
    title: 'Self-Membership Rights',
    description:
      'Principals with self-membership rights on groups. ' +
      'Allows adding oneself to a group, potentially gaining elevated privileges.',
    count: uniqueObjects.length,
    totalInstances: totalInstances !== uniqueObjects.length ? totalInstances : undefined,
    affectedEntities: includeDetails ? uniqueObjects : undefined,
  };
}
