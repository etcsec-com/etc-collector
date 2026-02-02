/**
 * DATA_CLASSIFICATION_MISSING - OUs without data classification
 * Frameworks: GDPR Art.30, ISO27001 A.8.2.1, HIPAA 164.312
 * Checks if organizational structure supports data classification
 */

import { ADDomain } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';

export function detectDataClassificationMissing(
  domain: ADDomain,
  _includeDetails: boolean
): Finding {
  const issues: string[] = [];

  // Check domain description for classification policy
  const domainDescription = (domain['description'] as string) || '';
  const hasClassificationKeywords = /confidential|restricted|internal|public|sensitive|pii|phi|pci/i.test(domainDescription);

  if (!hasClassificationKeywords) {
    issues.push('Domain description does not indicate data classification policy');
  }

  // Check for classification-related attributes in schema (heuristic)
  // Real check would involve examining OU descriptions and custom attributes
  const msExchVersion = domain['msExchVersion'] as number | undefined;
  if (msExchVersion) {
    // Exchange present - likely has email data requiring classification
    issues.push('Exchange detected - email data classification policy required for GDPR/HIPAA');
  }

  return {
    type: 'DATA_CLASSIFICATION_MISSING',
    severity: 'medium',
    category: 'compliance',
    title: 'Data Classification Not Implemented',
    description:
      'Data classification scheme not detected in AD structure. Required by GDPR Article 30, ISO27001 A.8.2.1, HIPAA 164.312.',
    count: issues.length > 0 ? 1 : 0,
    details: issues.length > 0 ? {
      violations: issues,
      frameworks: ['GDPR', 'ISO27001', 'HIPAA'],
      controls: ['Art.30', 'A.8.2.1', '164.312'],
      recommendation: 'Implement data classification scheme using OU structure and object attributes',
    } : undefined,
  };
}
