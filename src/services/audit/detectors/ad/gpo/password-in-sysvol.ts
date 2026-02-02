/**
 * GPO_PASSWORD_IN_SYSVOL - Passwords found in GPO preferences
 */

import { Finding } from '../../../../../types/finding.types';
import { ADGPO, GPOLink } from '../../../../../types/gpo.types';

/**
 * Detect GPOs with passwords stored in SYSVOL (cPassword)
 *
 * MS14-025 patched this, but old GPOs may still contain cleartext passwords
 * in Groups.xml, Services.xml, Scheduledtasks.xml, etc.
 *
 * @param gpos - Array of GPOs
 * @param _links - Array of GPO links (not used)
 * @param includeDetails - Whether to include affected entity details
 * @returns Finding for GPO_PASSWORD_IN_SYSVOL
 */
export function detectGpoPasswordInSysvol(
  gpos: ADGPO[],
  _links: GPOLink[],
  includeDetails: boolean
): Finding {
  // Check GPO flags or attributes that might indicate password presence
  // This would ideally need SYSVOL file content reading
  // For now, check for GPOs with "cpassword" mentioned or old-style preferences
  const affected = gpos.filter((gpo) => {
    const gpoName = (gpo.displayName || gpo.cn || '').toLowerCase();
    const gpoPath = (gpo.gPCFileSysPath || '').toLowerCase();

    // GPOs that commonly contain passwords
    const riskyPatterns = [
      'password',
      'credential',
      'local admin',
      'service account',
      'scheduled task',
      'drive map',
    ];

    return riskyPatterns.some(
      (pattern) => gpoName.includes(pattern) || gpoPath.includes(pattern)
    );
  });

  return {
    type: 'GPO_PASSWORD_IN_SYSVOL',
    severity: 'critical',
    category: 'gpo',
    title: 'Potential Passwords in GPO SYSVOL',
    description:
      'GPOs that may contain cleartext passwords in SYSVOL (cPassword vulnerability MS14-025). ' +
      'Group Policy Preferences stored passwords that can be easily decrypted.',
    count: affected.length,
    affectedEntities: includeDetails
      ? affected.map((g) => g.displayName || g.cn || g.dn)
      : undefined,
    details: {
      note: affected.length > 0
        ? `Found ${affected.length} GPO(s) with names suggesting password storage. Manual SYSVOL scan required.`
        : 'No GPOs with suspicious names found. Manual SYSVOL scan still recommended.',
      recommendation:
        'Scan SYSVOL for Groups.xml, Services.xml, ScheduledTasks.xml, DataSources.xml containing cpassword. ' +
        'Use tools like Get-GPPPassword or gpp-decrypt.',
      reference: 'MS14-025',
      gposScanned: gpos.length,
    },
  };
}
