/**
 * ESC10: Weak Certificate Mapping
 *
 * When strong certificate mapping is not enforced, attackers with ESC9 vulnerable
 * certificates can impersonate other users.
 * Note: This is a domain-level setting.
 */

import { Finding } from '../../../../../types/finding.types';

/**
 * Detect ESC10: Weak Certificate Mapping
 * When strong certificate mapping is not enforced, attackers with ESC9 vulnerable
 * certificates can impersonate other users
 * Note: This is a domain-level setting
 */
export function detectEsc10WeakCertificateMapping(
  domain: { dn: string; [key: string]: unknown } | null,
  _includeDetails: boolean
): Finding {
  // Certificate mapping strength is controlled by:
  // StrongCertificateBindingEnforcement registry key (HKLM\SYSTEM\CurrentControlSet\Services\Kdc)
  // 0 = Disabled, 1 = Compatibility mode (default), 2 = Full enforcement
  // Cannot be detected via LDAP - requires registry access

  // Also affected by CertificateMappingMethods registry key on DCs
  // UPN mapping without strong binding is vulnerable

  return {
    type: 'ESC10_WEAK_CERTIFICATE_MAPPING',
    severity: 'high',
    category: 'adcs',
    title: 'ESC10 - Certificate Mapping Configuration Review Required',
    description:
      'Domain controllers should be configured for strong certificate mapping to prevent certificate impersonation attacks. This setting cannot be detected via LDAP.',
    count: domain ? 1 : 0, // Flag as needing review if domain exists
    details: {
      note: 'Check StrongCertificateBindingEnforcement registry key on DCs. Value should be 2 (Full Enforcement).',
      registryPath:
        'HKLM\\SYSTEM\\CurrentControlSet\\Services\\Kdc\\StrongCertificateBindingEnforcement',
      recommendation:
        'Set StrongCertificateBindingEnforcement to 2 for full enforcement. Test in compatibility mode (1) first.',
      microsoftDoc:
        'https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers',
    },
  };
}
