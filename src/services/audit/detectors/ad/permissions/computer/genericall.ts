/**
 * COMPUTER_ACL_GENERICALL - GenericAll permission on computer objects
 */

import { AclEntry } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';
import { getUniqueObjects } from '../utils';

/**
 * Check for GenericAll permission on computer objects
 * PingCastle: Computer_ACL_GenericAll
 *
 * @param aclEntries - Array of ACL entries
 * @param includeDetails - Whether to include affected entity details
 * @param computerDns - Optional array of computer DNs for accurate matching
 */
export function detectComputerAclGenericAll(
  aclEntries: AclEntry[],
  includeDetails: boolean,
  computerDns?: string[]
): Finding {
  // GENERIC_ALL raw value
  const GENERIC_ALL = 0x10000000;
  // Full control mask for AD objects (all specific AD rights + standard rights)
  const AD_FULL_CONTROL = 0x000f01ff;

  // Build a Set of lowercase computer DNs for fast lookup
  const computerDnSet = new Set(
    computerDns ? computerDns.map((dn) => dn.toLowerCase()) : []
  );

  // Filter ACLs targeting computer objects
  const computerAcls = aclEntries.filter((ace) => {
    const dn = ace.objectDn.toLowerCase();

    // If we have a list of computer DNs, use exact matching
    if (computerDnSet.size > 0) {
      return computerDnSet.has(dn);
    }

    // Fallback: heuristic detection (less accurate)
    // Computer accounts end with $ in their sAMAccountName (which may appear in CN)
    const cnMatch = dn.match(/cn=([^,]+)/i);
    if (cnMatch && cnMatch[1] && cnMatch[1].endsWith('$')) {
      return true;
    }
    // Also check for computer-related OUs
    return (
      dn.includes('ou=computers') ||
      dn.includes('ou=workstations') ||
      dn.includes('ou=servers') ||
      dn.includes('cn=computers,')
    );
  });

  const affected = computerAcls.filter((ace) => {
    // Check for raw GENERIC_ALL
    if ((ace.accessMask & GENERIC_ALL) !== 0) return true;
    // Check for Full Control (GENERIC_ALL mapped to AD rights)
    return (ace.accessMask & AD_FULL_CONTROL) === AD_FULL_CONTROL;
  });

  const uniqueObjects = getUniqueObjects(affected);
  const totalInstances = affected.length;

  return {
    type: 'COMPUTER_ACL_GENERICALL',
    severity: 'high',
    category: 'permissions',
    title: 'Computer ACL GenericAll',
    description:
      'GenericAll permission on computer objects. Attacker with this permission can take over the computer, ' +
      'configure Resource-Based Constrained Delegation (RBCD), or extract credentials.',
    count: uniqueObjects.length,
    totalInstances: totalInstances !== uniqueObjects.length ? totalInstances : undefined,
    affectedEntities: includeDetails ? uniqueObjects : undefined,
  };
}
