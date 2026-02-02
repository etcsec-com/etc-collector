/**
 * ESC6 EDITF_ATTRIBUTESUBJECTALTNAME2 Detector
 * Check for ESC6 EDITF_ATTRIBUTESUBJECTALTNAME2
 */

import { Finding } from '../../../../../../types/finding.types';

export function detectEsc6EditfAttributeSubjectAltName2(cas: any[], includeDetails: boolean): Finding {
  const affected = cas.filter((ca) => {
    return ca.flags && (ca.flags & 0x40000) !== 0; // EDITF_ATTRIBUTESUBJECTALTNAME2
  });

  return {
    type: 'ESC6_EDITF_ATTRIBUTESUBJECTALTNAME2',
    severity: 'high',
    category: 'advanced',
    title: 'ESC6 EDITF Flag',
    description: 'ADCS CA with EDITF_ATTRIBUTESUBJECTALTNAME2 flag. Allows specifying arbitrary SAN in certificate requests.',
    count: affected.length,
    affectedEntities: includeDetails ? affected.map((ca) => ca.dn) : undefined,
  };
}
