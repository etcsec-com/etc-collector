/**
 * ESC2 Any Purpose Detector
 * Check for ESC2 Any Purpose EKU
 */

import { Finding } from '../../../../../../types/finding.types';

export function detectEsc2AnyPurpose(templates: any[], includeDetails: boolean): Finding {
  const affected = templates.filter((t) => {
    const hasAnyPurpose = t.pKIExtendedKeyUsage?.includes('2.5.29.37.0');
    const isEmpty = !t.pKIExtendedKeyUsage || t.pKIExtendedKeyUsage.length === 0;
    return hasAnyPurpose || isEmpty;
  });

  return {
    type: 'ESC2_ANY_PURPOSE',
    severity: 'high',
    category: 'advanced',
    title: 'ESC2 Any Purpose',
    description: 'ADCS template with Any Purpose EKU or no usage restriction. Certificate can be used for domain authentication.',
    count: affected.length,
    affectedEntities: includeDetails ? affected.map((t) => t.dn) : undefined,
  };
}
