/**
 * GPO_ORPHANED - Orphaned GPO (Phase 4)
 */

import { Finding } from '../../../../../types/finding.types';
import { ADGPO, GPOLink } from '../../../../../types/gpo.types';

/**
 * Detect orphaned GPOs
 *
 * GPOs that exist in AD but have missing SYSVOL content, or vice versa.
 *
 * @param gpos - Array of GPOs
 * @param _links - Array of GPO links (not used)
 * @param includeDetails - Whether to include affected entity details
 * @returns Finding for GPO_ORPHANED
 */
export function detectGpoOrphaned(
  gpos: ADGPO[],
  _links: GPOLink[],
  includeDetails: boolean
): Finding {
  // Check for GPOs with potential orphan indicators
  // A proper check would compare AD GPOs vs SYSVOL folders
  const affected = gpos.filter((gpo) => {
    // Missing SYSVOL path indicates potential orphan
    const hasSysvolPath = gpo.gPCFileSysPath && gpo.gPCFileSysPath.length > 0;
    // Missing version might indicate corruption
    const hasVersion = gpo.versionNumber !== undefined && gpo.versionNumber > 0;
    // Check for obviously broken GPOs
    const hasName = gpo.displayName || gpo.cn;

    return !hasSysvolPath || !hasVersion || !hasName;
  });

  return {
    type: 'GPO_ORPHANED',
    severity: 'medium',
    category: 'gpo',
    title: 'Potentially Orphaned GPOs',
    description:
      'GPOs that may be orphaned (missing SYSVOL content or AD object). ' +
      'Orphaned GPOs can cause processing errors and may indicate tampering.',
    count: affected.length,
    affectedEntities: includeDetails
      ? affected.map((g) => g.displayName || g.cn || g.dn)
      : undefined,
    details: {
      recommendation:
        'Compare AD GPOs with SYSVOL folders. Use gpotool.exe or Get-GPO to identify orphans. ' +
        'Delete orphaned GPOs after verification.',
    },
  };
}
