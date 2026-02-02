/**
 * Security Scoring Service
 *
 * Calculates security scores based on vulnerability findings
 * Story 1.7: AD Vulnerability Detection Engine
 *
 * Scoring Methodology (v1.1.1):
 * - Weighted Findings = (Critical × 10) + (High × 3) + (Medium × 1) + (Low × 0.2)
 * - Logarithmic scale to avoid extreme scores with high finding counts
 * - Security Score = max(0, min(100, 100 - log10(ratio + 1) * 50))
 *
 * Interpretation:
 * - 90-100: Excellent - Minimal vulnerabilities, strong security posture
 * - 70-89: Good - Some issues to address, generally secure
 * - 50-69: Fair - Multiple vulnerabilities requiring attention
 * - 30-49: Poor - Significant security gaps, urgent remediation needed
 * - 0-29: Critical - Severe security risk, immediate action required
 */

import { Finding, FindingCounts, CategoryCounts, Severity } from '../../types/finding.types';

/**
 * Security score result
 */
export interface SecurityScore {
  score: number;
  rating: 'excellent' | 'good' | 'fair' | 'poor' | 'critical';
  weightedPoints: number;
  totalUsers: number;
  findings: FindingCounts;
  categories: CategoryCounts;
}

/**
 * Severity weights for scoring (v1.1.0 - aligned with SaaS)
 */
const SEVERITY_WEIGHTS: Record<Severity, number> = {
  critical: 10,
  high: 3,
  medium: 1,
  low: 0.2,
};

/**
 * Calculate security score from findings
 *
 * @param findings Array of vulnerability findings
 * @param totalUsers Total number of users in the directory (for normalization)
 * @returns Security score object with rating and details
 */
export function calculateSecurityScore(findings: Finding[], totalUsers: number): SecurityScore {
  // Count findings by severity
  const counts: FindingCounts = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    total: 0,
  };

  // Count findings by category
  const categories: CategoryCounts = {
    passwords: 0,
    kerberos: 0,
    accounts: 0,
    groups: 0,
    computers: 0,
    advanced: 0,
    permissions: 0,
    config: 0,
    adcs: 0,
    gpo: 0,
    trusts: 0,
    'attack-paths': 0,
    monitoring: 0,
    compliance: 0,
    network: 0,
    identity: 0,
    applications: 0,
    conditionalAccess: 0,
    privilegedAccess: 0,
  };

  // Aggregate findings
  findings.forEach((finding) => {
    counts[finding.severity] += finding.count;
    counts.total += finding.count;
    categories[finding.category] += finding.count;
  });

  // Calculate weighted findings (v1.1.0 formula - aligned with SaaS)
  const weightedFindings =
    counts.critical * SEVERITY_WEIGHTS.critical +
    counts.high * SEVERITY_WEIGHTS.high +
    counts.medium * SEVERITY_WEIGHTS.medium +
    counts.low * SEVERITY_WEIGHTS.low;

  // Calculate security score (0-100) using logarithmic scale
  // This prevents extreme scores (always 0) with high finding counts
  // Multiplier 50 ensures vulnerable environments get appropriately low scores
  const totalEntities = Math.max(totalUsers, 1);
  const ratio = weightedFindings / totalEntities;
  const normalizedRatio = Math.log10(ratio + 1) * 50;
  const score = Math.max(0, Math.min(100, 100 - normalizedRatio));

  // Determine rating
  const rating = getSecurityRating(score);

  return {
    score: Math.round(score * 10) / 10, // Round to 1 decimal place
    rating,
    weightedPoints: weightedFindings,
    totalUsers,
    findings: counts,
    categories,
  };
}

/**
 * Get security rating from score
 *
 * @param score Security score (0-100)
 * @returns Rating category
 */
function getSecurityRating(score: number): 'excellent' | 'good' | 'fair' | 'poor' | 'critical' {
  if (score >= 90) return 'excellent';
  if (score >= 70) return 'good';
  if (score >= 50) return 'fair';
  if (score >= 30) return 'poor';
  return 'critical';
}

/**
 * Get human-readable description for rating
 *
 * @param rating Security rating
 * @returns Description string
 */
export function getRatingDescription(rating: string): string {
  const descriptions: Record<string, string> = {
    excellent: 'Excellent - Minimal vulnerabilities, strong security posture',
    good: 'Good - Some issues to address, generally secure',
    fair: 'Fair - Multiple vulnerabilities requiring attention',
    poor: 'Poor - Significant security gaps, urgent remediation needed',
    critical: 'Critical - Severe security risk, immediate action required',
  };

  return descriptions[rating] || 'Unknown rating';
}

/**
 * Calculate category-specific scores
 *
 * @param findings Array of vulnerability findings
 * @returns Map of category to score (0-100)
 */
export function calculateCategoryScores(findings: Finding[]): Record<string, number> {
  const categoryScores: Record<string, number> = {
    passwords: 100,
    kerberos: 100,
    accounts: 100,
    groups: 100,
    computers: 100,
    advanced: 100,
    permissions: 100,
    config: 100,
  };

  // Group findings by category
  const categoryFindings = findings.reduce((acc, finding) => {
    if (!acc[finding.category]) {
      acc[finding.category] = [];
    }
    acc[finding.category]!.push(finding);
    return acc;
  }, {} as Record<string, Finding[]>);

  // Calculate score for each category
  Object.keys(categoryFindings).forEach((category) => {
    const categoryFindingsList = categoryFindings[category];
    if (!categoryFindingsList) return;

    const weightedPoints = categoryFindingsList.reduce((sum, finding) => {
      return sum + finding.count * SEVERITY_WEIGHTS[finding.severity];
    }, 0);

    // Simple deduction: -1 point per weighted point (capped at 0)
    categoryScores[category] = Math.max(0, 100 - weightedPoints);
  });

  return categoryScores;
}

/**
 * Get top N most critical findings
 *
 * @param findings Array of vulnerability findings
 * @param limit Number of findings to return
 * @returns Top N findings sorted by severity and count
 */
export function getTopFindings(findings: Finding[], limit: number = 10): Finding[] {
  // Sort by severity weight * count (descending)
  const sorted = [...findings].sort((a, b) => {
    const weightA = SEVERITY_WEIGHTS[a.severity] * a.count;
    const weightB = SEVERITY_WEIGHTS[b.severity] * b.count;
    return weightB - weightA;
  });

  return sorted.slice(0, limit);
}

/**
 * Generate security summary
 *
 * @param score Security score object
 * @returns Human-readable summary string
 */
export function generateSecuritySummary(score: SecurityScore): string {
  const { score: scoreValue, rating, findings } = score;

  const lines = [
    `Security Score: ${scoreValue}/100 (${rating.toUpperCase()})`,
    getRatingDescription(rating),
    '',
    'Vulnerability Summary:',
    `- Critical: ${findings.critical}`,
    `- High: ${findings.high}`,
    `- Medium: ${findings.medium}`,
    `- Low: ${findings.low}`,
    `- Total: ${findings.total}`,
  ];

  return lines.join('\n');
}
