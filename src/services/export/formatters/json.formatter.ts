/**
 * JSON Formatter
 *
 * Formats audit results as JSON for export.
 * Story 1.9: Export Service
 *
 * Output structure:
 * - metadata: timestamp, provider, domain, duration, version
 * - summary: score, total findings, breakdown by severity and category
 * - findings: detailed vulnerability list
 * - stats: entity counts, execution time
 */

import { Finding } from '../../../types/finding.types';
import { SecurityScore } from '../../audit/scoring.service';

/**
 * JSON export result structure
 */
export interface JSONExportResult {
  metadata: {
    timestamp: string;
    provider: 'ad' | 'azure';
    domain?: string;
    tenantId?: string;
    executionTimeMs: number;
    version: string;
  };
  summary: {
    score: SecurityScore;
    totalFindings: number;
    severityBreakdown: {
      critical: number;
      high: number;
      medium: number;
      low: number;
    };
    categoryBreakdown: Record<string, number>;
  };
  findings: Finding[];
  stats: {
    totalUsers?: number;
    totalGroups?: number;
    totalComputers?: number;
    totalApps?: number;
    totalPolicies?: number;
  };
}

/**
 * Export options for JSON formatter
 */
export interface JSONExportOptions {
  /**
   * Provider type (ad or azure)
   */
  provider: 'ad' | 'azure';

  /**
   * Domain name for AD or Tenant ID for Azure
   */
  domain?: string;

  /**
   * Tenant ID for Azure exports
   */
  tenantId?: string;

  /**
   * Include detailed entities in findings (default: false)
   */
  includeDetails?: boolean;
}

/**
 * Format audit results as JSON
 *
 * @param score Security score
 * @param findings Vulnerability findings
 * @param stats Statistics (entity counts, execution time)
 * @param options Export options
 * @returns JSON string
 */
export function formatAsJSON(
  score: SecurityScore,
  findings: Finding[],
  stats: Record<string, number>,
  options: JSONExportOptions
): string {
  const timestamp = new Date().toISOString();

  // Calculate severity breakdown
  const severityBreakdown = {
    critical: findings.filter((f) => f.severity === 'critical').reduce((sum, f) => sum + f.count, 0),
    high: findings.filter((f) => f.severity === 'high').reduce((sum, f) => sum + f.count, 0),
    medium: findings.filter((f) => f.severity === 'medium').reduce((sum, f) => sum + f.count, 0),
    low: findings.filter((f) => f.severity === 'low').reduce((sum, f) => sum + f.count, 0),
  };

  // Calculate category breakdown
  const categoryBreakdown: Record<string, number> = {};
  findings.forEach((finding) => {
    const category = finding.category;
    if (!categoryBreakdown[category]) {
      categoryBreakdown[category] = 0;
    }
    categoryBreakdown[category] += finding.count;
  });

  // Build export result
  const result: JSONExportResult = {
    metadata: {
      timestamp,
      provider: options.provider,
      domain: options.domain,
      tenantId: options.tenantId,
      executionTimeMs: stats['executionTimeMs'] || 0,
      version: '1.1.9',
    },
    summary: {
      score,
      totalFindings: findings.reduce((sum, f) => sum + f.count, 0),
      severityBreakdown,
      categoryBreakdown,
    },
    findings: options.includeDetails
      ? findings
      : findings.map((f) => {
          const { affectedEntities, ...rest } = f;
          return rest;
        }),
    stats: {
      totalUsers: stats['totalUsers'],
      totalGroups: stats['totalGroups'],
      totalComputers: stats['totalComputers'],
      totalApps: stats['totalApps'],
      totalPolicies: stats['totalPolicies'],
    },
  };

  return JSON.stringify(result, null, 2);
}

/**
 * Generate Content-Disposition header value for JSON export
 *
 * Format: `attachment; filename="audit-{provider}-{domain}-{timestamp}.json"`
 * Example: `attachment; filename="audit-ad-EXAMPLE-2026-01-12T10-30-00Z.json"`
 *
 * @param provider Provider type (ad or azure)
 * @param domain Domain name or tenant ID
 * @returns Content-Disposition header value
 */
export function getJSONContentDisposition(provider: string, domain: string): string {
  const timestamp = new Date().toISOString().replace(/:/g, '-').replace(/\..+/, 'Z');
  const sanitizedDomain = domain.replace(/[^a-zA-Z0-9-_]/g, '-');
  const filename = `audit-${provider}-${sanitizedDomain}-${timestamp}.json`;

  return `attachment; filename="${filename}"`;
}
