/**
 * GPO_DISABLED_BUT_LINKED - GPO is disabled but still linked
 */

import { Finding } from '../../../../../types/finding.types';
import { ADGPO, GPOLink, GPO_FLAG_ALL_DISABLED } from '../../../../../types/gpo.types';

/**
 * GPO_DISABLED_BUT_LINKED: GPO is disabled but still linked
 */
export function detectGpoDisabledButLinked(
  gpos: ADGPO[],
  links: GPOLink[],
  includeDetails: boolean
): Finding {
  // Find GPOs that are disabled (flags = 3) but have active links
  const disabledGpos = gpos.filter((gpo) => gpo.flags === GPO_FLAG_ALL_DISABLED);

  const disabledButLinked = disabledGpos.filter((gpo) =>
    links.some((link) => link.gpoGuid.toLowerCase() === gpo.cn.toLowerCase() && !link.disabled)
  );

  return {
    type: 'GPO_DISABLED_BUT_LINKED',
    severity: 'medium',
    category: 'gpo',
    title: 'Disabled GPO Still Linked',
    description:
      'GPOs are disabled (both user and computer settings) but remain linked. This may indicate configuration drift or incomplete changes.',
    count: disabledButLinked.length,
    affectedEntities: includeDetails
      ? disabledButLinked.map((gpo) => gpo.displayName || gpo.cn)
      : undefined,
  };
}
