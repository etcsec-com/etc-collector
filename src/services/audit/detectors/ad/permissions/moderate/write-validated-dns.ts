/**
 * ACL_COMPUTER_WRITE_VALIDATED_DNS - Validated-Write-DNS rights on computers
 */

import { AclEntry } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';
import { getUniqueObjects } from '../utils';

/**
 * Detect Validated-Write-DNS rights on computers
 *
 * This right allows modifying DNS records for computers.
 *
 * @param aclEntries - Array of ACL entries
 * @param includeDetails - Whether to include affected entity details
 * @returns Finding for ACL_COMPUTER_WRITE_VALIDATED_DNS
 */
export function detectAclComputerWriteValidatedDns(
  aclEntries: AclEntry[],
  includeDetails: boolean
): Finding {
  // Validated-Write to DNS-Host-Name: 72e39547-7b18-11d1-adef-00c04fd8d5cd
  const VALIDATED_DNS_GUID = '72e39547-7b18-11d1-adef-00c04fd8d5cd';

  const affected = aclEntries.filter((ace) => {
    const isComputerObject = ace.objectDn.toLowerCase().includes('cn=computers');
    const hasDnsRight = ace.objectType?.toLowerCase() === VALIDATED_DNS_GUID;
    return isComputerObject && hasDnsRight;
  });

  const uniqueObjects = getUniqueObjects(affected);
  const totalInstances = affected.length;

  return {
    type: 'ACL_COMPUTER_WRITE_VALIDATED_DNS',
    severity: 'medium',
    category: 'permissions',
    title: 'Validated-Write-DNS on Computers',
    description:
      'Principals with rights to modify DNS host names on computer objects. ' +
      'Can be used for DNS spoofing and MITM attacks.',
    count: uniqueObjects.length,
    totalInstances: totalInstances !== uniqueObjects.length ? totalInstances : undefined,
    affectedEntities: includeDetails ? uniqueObjects : undefined,
  };
}
