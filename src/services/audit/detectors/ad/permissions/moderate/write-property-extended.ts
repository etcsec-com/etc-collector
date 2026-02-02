/**
 * ACL_WRITE_PROPERTY_EXTENDED - Extended write property rights
 */

import { AclEntry } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';
import { getUniqueObjects } from '../utils';

/**
 * Detect extended write property rights
 *
 * Extended write property rights can be abused for various attacks.
 *
 * @param aclEntries - Array of ACL entries
 * @param includeDetails - Whether to include affected entity details
 * @returns Finding for ACL_WRITE_PROPERTY_EXTENDED
 */
export function detectAclWritePropertyExtended(
  aclEntries: AclEntry[],
  includeDetails: boolean
): Finding {
  // Common dangerous extended properties
  const DANGEROUS_PROPERTIES = [
    '00299570-246d-11d0-a768-00aa006e0529', // User-Force-Change-Password
    'bf967a68-0de6-11d0-a285-00aa003049e2', // Script-Path
    'bf967950-0de6-11d0-a285-00aa003049e2', // Home-Directory
    '5f202010-79a5-11d0-9020-00c04fc2d4cf', // ms-DS-Key-Credential-Link (Shadow Credentials)
  ];

  const WRITE_PROPERTY = 0x20;

  const affected = aclEntries.filter((ace) => {
    const hasWriteProperty = (ace.accessMask & WRITE_PROPERTY) !== 0;
    const isDangerousProperty =
      ace.objectType && DANGEROUS_PROPERTIES.includes(ace.objectType.toLowerCase());
    return hasWriteProperty && isDangerousProperty;
  });

  const uniqueObjects = getUniqueObjects(affected);
  const totalInstances = affected.length;

  return {
    type: 'ACL_WRITE_PROPERTY_EXTENDED',
    severity: 'medium',
    category: 'permissions',
    title: 'Extended Write Property Rights',
    description:
      'Principals with dangerous extended write property rights. ' +
      'Can modify script paths, home directories, or key credentials.',
    count: uniqueObjects.length,
    totalInstances: totalInstances !== uniqueObjects.length ? totalInstances : undefined,
    affectedEntities: includeDetails ? uniqueObjects : undefined,
  };
}
