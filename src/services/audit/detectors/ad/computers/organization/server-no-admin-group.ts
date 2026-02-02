/**
 * Server No Admin Group Detector
 * Detect servers without local admin groups properly configured
 * Servers should have documented local administrators
 */

import { ADComputer } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';
import { toAffectedComputerEntities, ldapAttrToString } from '../../../../../../utils/entity-converter';

export function detectServerNoAdminGroup(computers: ADComputer[], includeDetails: boolean): Finding {
  const serverPatterns = [/server/i, /^srv/i, /^sql/i, /^web/i, /^app/i, /^db/i, /^file/i];
  const serverOsPatterns = [/server/i];

  const affected = computers.filter((c) => {
    // Check if it's a server
    const os = ldapAttrToString(c.operatingSystem);
    const isServer =
      serverPatterns.some((p) => p.test(c.sAMAccountName || '')) ||
      (os && serverOsPatterns.some((p) => p.test(os)));

    if (!isServer) return false;

    // Check if it's enabled
    if (!c.enabled) return false;

    // Check if there's a corresponding admin group (naming convention: ServerName-Admins or similar)
    // This is a heuristic - we flag servers that might not have managed admin groups
    // In practice, this would need to be verified against a CMDB or documented standard

    // Flag if it's a server with description indicating it's unmanaged
    const rawDesc = c['description'];
    const description = (typeof rawDesc === 'string' ? rawDesc : (Array.isArray(rawDesc) ? rawDesc[0] : '') || '').toLowerCase();
    const isUnmanaged =
      description.includes('unmanaged') ||
      description.includes('legacy') ||
      description.includes('deprecated');

    return isUnmanaged;
  });

  return {
    type: 'SERVER_NO_ADMIN_GROUP',
    severity: 'medium',
    category: 'computers',
    title: 'Server Without Managed Admin Group',
    description:
      'Servers identified as unmanaged or without proper administrative group documentation. Local admin access may not be properly controlled.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedComputerEntities(affected) : undefined,
    details:
      affected.length > 0
        ? {
            recommendation:
              'Create dedicated admin groups for each server (e.g., SRV01-Admins) and document access.',
            risks: [
              'Unknown administrators may have access',
              'Audit trail for admin actions may be incomplete',
              'Compliance violations for access management',
            ],
          }
        : undefined,
  };
}
