/**
 * ESC8: NTLM Relay to AD CS HTTP Endpoint
 *
 * Web enrollment enabled over HTTP (allows NTLM relay attacks).
 * Note: Cannot be fully detected via LDAP - requires network probing.
 */

import { Finding } from '../../../../../types/finding.types';
import { ADCSCertificateAuthority } from '../../../../../types/adcs.types';

/**
 * Detect ESC8: NTLM Relay to AD CS HTTP Endpoint
 * Web enrollment enabled over HTTP (allows NTLM relay attacks)
 * Note: Cannot be fully detected via LDAP - requires network probing
 */
export function detectEsc8HttpEnrollment(
  cas: ADCSCertificateAuthority[],
  includeDetails: boolean
): Finding {
  // HTTP enrollment endpoints are typically at:
  // http://<CA>/certsrv/
  // Cannot detect via LDAP alone - would need network connectivity check

  return {
    type: 'ESC8_HTTP_ENROLLMENT',
    severity: 'medium',
    category: 'adcs',
    title: 'ESC8 - Web Enrollment Check Required',
    description:
      'Certificate Authorities should be checked for HTTP-based web enrollment endpoints which are vulnerable to NTLM relay attacks.',
    count: 0, // Cannot detect via LDAP
    affectedEntities: includeDetails ? cas.map((ca) => `${ca.dNSHostName || ca.name}`) : undefined,
    details: {
      note: 'Check for http://<CA>/certsrv/ endpoints. HTTPS with Extended Protection mitigates this.',
      casToCheck: cas.length,
    },
  };
}
