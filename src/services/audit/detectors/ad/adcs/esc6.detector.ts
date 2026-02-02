/**
 * ESC6: EDITF_ATTRIBUTESUBJECTALTNAME2 Flag
 *
 * CA configured to allow requestor-specified SAN for any template.
 * Note: This flag is in registry, not LDAP - cannot detect via pure LDAP.
 */

import { Finding } from '../../../../../types/finding.types';
import { ADCSCertificateAuthority } from '../../../../../types/adcs.types';

/**
 * Detect ESC6: EDITF_ATTRIBUTESUBJECTALTNAME2 Flag
 * CA configured to allow requestor-specified SAN for any template
 * Note: This flag is in registry, not LDAP - cannot detect via pure LDAP
 */
export function detectEsc6EditfFlag(
  cas: ADCSCertificateAuthority[],
  includeDetails: boolean
): Finding {
  // EDITF_ATTRIBUTESUBJECTALTNAME2 (0x00040000) is stored in registry at:
  // HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA Name>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\EditFlags
  // Cannot be detected via LDAP alone

  return {
    type: 'ESC6_EDITF_FLAG',
    severity: 'high',
    category: 'adcs',
    title: 'ESC6 - CA Configuration Review Required',
    description:
      'Certificate Authorities should be checked for EDITF_ATTRIBUTESUBJECTALTNAME2 flag which allows any certificate requestor to specify a SAN.',
    count: 0, // Cannot detect via LDAP
    affectedEntities: includeDetails ? cas.map((ca) => ca.name || ca.dn) : undefined,
    details: {
      note: 'Check registry key EditFlags on CA servers. Flag 0x00040000 indicates vulnerability.',
      casToCheck: cas.length,
    },
  };
}
