/**
 * GPO_UNLINKED - GPO exists but not linked anywhere
 */

import { Finding } from '../../../../../types/finding.types';
import { ADGPO, GPOLink } from '../../../../../types/gpo.types';

/**
 * GPO_UNLINKED: GPO exists but not linked anywhere
 */
export function detectGpoUnlinked(
  gpos: ADGPO[],
  links: GPOLink[],
  includeDetails: boolean
): Finding {
  // Find GPOs that have no links
  const linkedGuids = new Set(links.map((l) => l.gpoGuid.toLowerCase()));
  const unlinkedGpos = gpos.filter((gpo) => !linkedGuids.has(gpo.cn.toLowerCase()));

  // Exclude Default Domain Policy and Default Domain Controllers Policy
  const excludeGuids = [
    '31B2F340-016D-11D2-945F-00C04FB984F9', // Default Domain Policy
    '6AC1786C-016F-11D2-945F-00C04FB984F9', // Default Domain Controllers Policy
  ];

  const relevantUnlinked = unlinkedGpos.filter(
    (gpo) => !excludeGuids.some((guid) => gpo.cn.toUpperCase().includes(guid))
  );

  return {
    type: 'GPO_UNLINKED',
    severity: 'low',
    category: 'gpo',
    title: 'Unlinked Group Policy Objects',
    description:
      'GPOs exist that are not linked to any OU, domain, or site. These may be orphaned or indicate incomplete deployment.',
    count: relevantUnlinked.length,
    affectedEntities: includeDetails
      ? relevantUnlinked.map((gpo) => gpo.displayName || gpo.cn)
      : undefined,
  };
}
