/**
 * ESC11: IF_ENFORCEENCRYPTICERTREQUEST Not Enforced
 *
 * When RPC encryption is not enforced on the CA, attackers can relay NTLM
 * authentication to the CA's RPC endpoint.
 * Note: This is a CA configuration setting.
 */

import { Finding } from '../../../../../types/finding.types';
import { ADCSCertificateAuthority } from '../../../../../types/adcs.types';

/**
 * Detect ESC11: IF_ENFORCEENCRYPTICERTREQUEST Not Enforced
 * When RPC encryption is not enforced on the CA, attackers can relay NTLM
 * authentication to the CA's RPC endpoint
 * Note: This is a CA configuration setting
 */
export function detectEsc11IcertRequestEnforcement(
  cas: ADCSCertificateAuthority[],
  includeDetails: boolean
): Finding {
  // IF_ENFORCEENCRYPTICERTREQUEST is stored in registry at:
  // HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA>\InterfaceFlags
  // Flag 0x00000200 should be set to enforce RPC encryption
  // Cannot be detected via LDAP alone

  return {
    type: 'ESC11_ICERT_REQUEST_ENFORCEMENT',
    severity: 'medium',
    category: 'adcs',
    title: 'ESC11 - RPC Encryption Enforcement Check Required',
    description:
      'Certificate Authorities should enforce RPC encryption (IF_ENFORCEENCRYPTICERTREQUEST flag) to prevent NTLM relay attacks to the ICertPassage RPC interface.',
    count: cas.length > 0 ? 1 : 0, // Flag as needing review if CAs exist
    affectedEntities: includeDetails ? cas.map((ca) => ca.name || ca.dn) : undefined,
    details: {
      note: 'Check InterfaceFlags registry key on CA servers. Flag 0x00000200 (IF_ENFORCEENCRYPTICERTREQUEST) should be set.',
      registryPath:
        'HKLM\\SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\<CA>\\InterfaceFlags',
      casToCheck: cas.length,
      recommendation:
        'Set IF_ENFORCEENCRYPTICERTREQUEST flag using: certutil -setreg CA\\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST',
    },
  };
}
