/**
 * Kerberoasting Risk Detector
 *
 * Detects user accounts with Service Principal Names (SPNs).
 * Accounts with SPNs are vulnerable to Kerberoasting attacks.
 */

import { ADUser } from '../../../../../types/ad.types';
import { Finding } from '../../../../../types/finding.types';
import { toAffectedUserEntities } from '../../../../../utils/entity-converter';

/**
 * Check for Kerberoasting risk (user with SPN)
 */
export function detectKerberoastingRisk(users: ADUser[], includeDetails: boolean): Finding {
  const affected = users.filter((u) => {
    const spns = (u as any)['servicePrincipalName'];
    return spns && Array.isArray(spns) && spns.length > 0;
  });

  return {
    type: 'KERBEROASTING_RISK',
    severity: 'high',
    category: 'kerberos',
    title: 'Kerberoasting Risk',
    description: 'User accounts with Service Principal Names (SPNs). Vulnerable to Kerberoasting attacks to crack service account passwords.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected) : undefined,
  };
}
