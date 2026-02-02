/**
 * DC Not in DC OU Detector
 * Detect Domain Controllers not in Domain Controllers OU
 * DCs should always be in the default Domain Controllers OU
 */

import { ADComputer } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';
import { toAffectedComputerEntities } from '../../../../../../utils/entity-converter';

export function detectDcNotInDcOu(computers: ADComputer[], includeDetails: boolean): Finding {
  const dcPatterns = [/^DC\d*/i, /domain controller/i];

  const affected = computers.filter((c) => {
    // Check if it's a domain controller
    const dnsName = typeof c.dNSHostName === 'string' ? c.dNSHostName : (Array.isArray(c.dNSHostName) ? c.dNSHostName[0] : '');
    const isDC =
      dcPatterns.some((p) => p.test(c.sAMAccountName || '')) ||
      (dnsName && dnsName.toLowerCase().includes('dc')) ||
      ((c.userAccountControl ?? 0) & 0x2000) !== 0; // SERVER_TRUST_ACCOUNT flag

    if (!isDC) return false;

    // Check if it's in the Domain Controllers OU
    const isInDCOU = c.dn.toLowerCase().includes('ou=domain controllers');

    return !isInDCOU;
  });

  return {
    type: 'DC_NOT_IN_DC_OU',
    severity: 'high',
    category: 'computers',
    title: 'Domain Controller Not in Domain Controllers OU',
    description:
      'Domain Controllers found outside the Domain Controllers OU. This may indicate misconfiguration or an attempt to hide a rogue DC.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedComputerEntities(affected) : undefined,
    details:
      affected.length > 0
        ? {
            recommendation:
              'Move all Domain Controllers to the Domain Controllers OU for proper GPO application and management.',
            risks: [
              'GPOs targeting Domain Controllers OU may not apply',
              'May indicate rogue or compromised DC',
              'Security baselines may not be applied correctly',
            ],
          }
        : undefined,
  };
}
