/**
 * Compliance Score Calculator
 * Calculate overall compliance score across all frameworks
 */

import { Finding } from '../../../../../types/finding.types';
import { FrameworkScore } from './types';

/**
 * Calculate overall compliance score
 * Provides a summary of compliance across all frameworks
 */
export function detectComplianceScore(
  findings: Finding[],
  _includeDetails: boolean
): Finding {
  // Count compliance findings by framework
  const anssi: FrameworkScore = { total: 5, passed: 0 };
  const nist: FrameworkScore = { total: 4, passed: 0 };
  const cis: FrameworkScore = { total: 3, passed: 0 };
  const disa: FrameworkScore = { total: 2, passed: 0 };
  const industry: FrameworkScore = { total: 8, passed: 0 }; // PCI-DSS, SOC2, GDPR, SOX, DORA, HIPAA, ISO27001

  // Industry framework detection types
  const industryTypes = [
    'MFA_NOT_ENFORCED',
    'BACKUP_AD_NOT_VERIFIED',
    'AUDIT_LOG_RETENTION_SHORT',
    'PRIVILEGED_ACCESS_REVIEW_MISSING',
    'DATA_CLASSIFICATION_MISSING',
    'CHANGE_MANAGEMENT_BYPASS',
    'VENDOR_ACCOUNT_UNMONITORED',
    'ENCRYPTION_AT_REST_DISABLED',
  ];

  // Check each compliance finding
  const complianceFindings = findings.filter((f) => f.category === 'compliance');

  for (const finding of complianceFindings) {
    if (finding.count === 0) {
      if (finding.type.startsWith('ANSSI_')) anssi.passed++;
      else if (finding.type.startsWith('NIST_')) nist.passed++;
      else if (finding.type.startsWith('CIS_')) cis.passed++;
      else if (finding.type.startsWith('DISA_')) disa.passed++;
      else if (industryTypes.includes(finding.type)) industry.passed++;
    }
  }

  // Calculate overall score
  const totalControls = anssi.total + nist.total + cis.total + disa.total + industry.total;
  const passedControls = anssi.passed + nist.passed + cis.passed + disa.passed + industry.passed;
  const compliancePercentage = Math.round((passedControls / totalControls) * 100);

  return {
    type: 'COMPLIANCE_SCORE',
    severity: 'low',
    category: 'compliance',
    title: 'Compliance Score Summary',
    description: `Overall compliance score: ${compliancePercentage}%. This represents adherence to ANSSI, NIST, CIS, DISA, and industry frameworks (PCI-DSS, SOC2, GDPR, SOX, DORA, HIPAA, ISO27001).`,
    count: totalControls - passedControls, // Non-compliant controls
    details: {
      score: compliancePercentage,
      frameworks: {
        ANSSI: `${anssi.passed}/${anssi.total}`,
        NIST: `${nist.passed}/${nist.total}`,
        CIS: `${cis.passed}/${cis.total}`,
        DISA: `${disa.passed}/${disa.total}`,
        'Industry (PCI/SOC2/GDPR/SOX/DORA/HIPAA/ISO)': `${industry.passed}/${industry.total}`,
      },
      passedControls,
      totalControls,
      recommendation:
        compliancePercentage < 70
          ? 'Compliance score is below 70%. Prioritize addressing high-severity compliance gaps.'
          : undefined,
    },
  };
}
