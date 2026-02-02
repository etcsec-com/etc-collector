/**
 * ESC9: No Security Extension (szOID_NTDS_CA_SECURITY_EXT)
 *
 * Certificates without the new security extension are vulnerable to impersonation
 * when strong certificate mapping is not enforced.
 * Note: Requires template schema version check.
 */

import { Finding } from '../../../../../types/finding.types';
import { ADCSCertificateTemplate } from '../../../../../types/adcs.types';
import { hasAuthenticationEku } from './utils';

/**
 * Detect ESC9: No Security Extension (szOID_NTDS_CA_SECURITY_EXT)
 * Certificates without the new security extension are vulnerable to impersonation
 * when strong certificate mapping is not enforced
 * Note: Requires template schema version check
 */
export function detectEsc9NoSecurityExtension(
  templates: ADCSCertificateTemplate[],
  includeDetails: boolean
): Finding {
  // Templates with schema version < 2 don't include security extension
  // msPKI-Template-Schema-Version attribute determines this
  const affected = templates.filter((t) => {
    const schemaVersion = t['msPKI-Template-Schema-Version'] || 1;
    const ekus = t.pKIExtendedKeyUsage || [];

    // Vulnerable if: old schema AND can authenticate
    return schemaVersion < 2 && hasAuthenticationEku(ekus);
  });

  return {
    type: 'ESC9_NO_SECURITY_EXTENSION',
    severity: 'high',
    category: 'adcs',
    title: 'ESC9 - No Security Extension in Certificate Template',
    description:
      'Certificate templates using schema version 1 do not include the szOID_NTDS_CA_SECURITY_EXT security extension. Combined with weak certificate mapping, this allows certificate impersonation attacks.',
    count: affected.length,
    affectedEntities: includeDetails ? affected.map((t) => t.name || t.displayName || t.dn) : undefined,
    details:
      affected.length > 0
        ? {
            recommendation:
              'Upgrade certificate templates to schema version 2 or higher, and enable strong certificate mapping.',
            vulnerabilityChain: 'ESC9 + weak certificate mapping = impersonation',
          }
        : undefined,
  };
}
