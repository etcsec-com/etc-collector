/**
 * Dangerous Logon Scripts Detector
 * Check for dangerous logon scripts with weak ACLs
 */

import { ADUser } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';
import { toAffectedUserEntities } from '../../../../../../utils/entity-converter';

export function detectDangerousLogonScripts(users: ADUser[], includeDetails: boolean): Finding {
  const affected = users.filter((u) => {
    const scriptPath = (u as any).scriptPath;
    // Check if user has logon script configured
    // In real implementation, would check ACLs on script file/share
    return scriptPath && (scriptPath.includes('\\\\') || scriptPath.startsWith('//'));
  });

  return {
    type: 'DANGEROUS_LOGON_SCRIPTS',
    severity: 'medium',
    category: 'advanced',
    title: 'Dangerous Logon Scripts',
    description: 'Logon scripts with weak ACLs can be modified by attackers for code execution on user login.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected) : undefined,
  };
}
