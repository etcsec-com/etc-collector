/**
 * DANGEROUS_GROUP_NESTING - Sensitive groups nested in less sensitive groups
 */

import { ADGroup } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';
import { toAffectedADGroupEntities } from '../../../../../../utils/entity-converter';

/**
 * Check for dangerous group nesting (sensitive groups nested in less sensitive groups)
 */
export function detectDangerousGroupNesting(groups: ADGroup[], includeDetails: boolean): Finding {
  const protectedGroups = [
    'Domain Admins',
    'Enterprise Admins',
    'Schema Admins',
    'Administrators',
    'Account Operators',
    'Backup Operators',
    'Server Operators',
    'Print Operators',
  ];

  const affected = groups.filter((g) => {
    if (!g.memberOf) return false;

    // Check if this is a protected group
    const isProtected = protectedGroups.some((pg) => g.dn.includes(`CN=${pg}`));
    if (!isProtected) return false;

    // Check if it's nested in a non-protected group
    const hasUnexpectedNesting = g.memberOf.some((dn) => {
      return !protectedGroups.some((pg) => dn.includes(`CN=${pg}`));
    });

    return hasUnexpectedNesting;
  });

  return {
    type: 'DANGEROUS_GROUP_NESTING',
    severity: 'medium',
    category: 'groups',
    title: 'Dangerous Group Nesting',
    description: 'Sensitive group nested in less sensitive group. Unintended privilege escalation path.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedADGroupEntities(affected) : undefined,
  };
}
