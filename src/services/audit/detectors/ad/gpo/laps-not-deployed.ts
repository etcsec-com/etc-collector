/**
 * GPO_LAPS_NOT_DEPLOYED - No LAPS deployment GPO found
 */

import { Finding } from '../../../../../types/finding.types';
import { ADGPO, GPOLink } from '../../../../../types/gpo.types';
import { hasLapsCse } from './types';

/**
 * GPO_LAPS_NOT_DEPLOYED: No LAPS deployment GPO found
 */
export function detectGpoLapsNotDeployed(
  gpos: ADGPO[],
  links: GPOLink[],
  _includeDetails: boolean
): Finding {
  // Check if any GPO has LAPS CSE and is linked
  const lapsGpos = gpos.filter((gpo) => hasLapsCse(gpo));
  const linkedLapsGpos = lapsGpos.filter((gpo) =>
    links.some((link) => link.gpoGuid.toLowerCase() === gpo.cn.toLowerCase() && !link.disabled)
  );

  const noLapsDeployed = linkedLapsGpos.length === 0;

  return {
    type: 'GPO_LAPS_NOT_DEPLOYED',
    severity: 'medium',
    category: 'gpo',
    title: 'LAPS Not Deployed via GPO',
    description:
      'No active Group Policy Object was found deploying LAPS (Local Administrator Password Solution). This leaves local admin passwords vulnerable to reuse attacks.',
    count: noLapsDeployed ? 1 : 0,
    affectedEntities: undefined,
    details: {
      lapsGposFound: lapsGpos.length,
      linkedLapsGpos: linkedLapsGpos.length,
      note: noLapsDeployed
        ? 'LAPS not deployed - local admin passwords are not being rotated.'
        : 'LAPS is deployed via GPO.',
      recommendation: noLapsDeployed
        ? 'Deploy LAPS via GPO to manage local administrator passwords.'
        : undefined,
    },
  };
}
