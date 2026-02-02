/**
 * Export Service
 *
 * Orchestrates audit result export to JSON and CSV formats.
 * Story 1.9: Export Service
 *
 * Features:
 * - JSON export with full audit structure
 * - CSV export with flat table structure
 * - Content-Disposition headers for file downloads
 * - Excel-compatible CSV (UTF-8 with BOM)
 */

import { Finding } from '../../types/finding.types';
import { SecurityScore } from '../audit/scoring.service';
import { formatAsJSON, getJSONContentDisposition, JSONExportOptions } from './formatters/json.formatter';
import { formatAsCSV, getCSVContentDisposition, CSVExportOptions } from './formatters/csv.formatter';

/**
 * Audit result for export
 */
export interface ExportAuditResult {
  score: SecurityScore;
  findings: Finding[];
  stats: {
    totalUsers?: number;
    totalGroups?: number;
    totalComputers?: number;
    totalApps?: number;
    totalPolicies?: number;
    totalFindings: number;
    executionTimeMs: number;
  };
  timestamp: Date;
}

/**
 * Export result with content and headers
 */
export interface ExportResult {
  content: string;
  contentType: string;
  contentDisposition: string;
}

/**
 * Export Service
 */
export class ExportService {
  /**
   * Export audit result as JSON
   *
   * @param auditResult Audit result
   * @param options JSON export options
   * @returns Export result with JSON content and headers
   */
  exportToJSON(auditResult: ExportAuditResult, options: JSONExportOptions): ExportResult {
    // Format as JSON
    const content = formatAsJSON(auditResult.score, auditResult.findings, auditResult.stats, options);

    // Generate Content-Disposition header
    const domain = options.domain || options.tenantId || 'unknown';
    const contentDisposition = getJSONContentDisposition(options.provider, domain);

    return {
      content,
      contentType: 'application/json; charset=utf-8',
      contentDisposition,
    };
  }

  /**
   * Export audit result as CSV
   *
   * @param auditResult Audit result
   * @param provider Provider type (ad or azure)
   * @param domain Domain name or tenant ID
   * @param options CSV export options
   * @returns Export result with CSV content and headers
   */
  exportToCSV(
    auditResult: ExportAuditResult,
    provider: string,
    domain: string,
    options: CSVExportOptions = {}
  ): ExportResult {
    // Format as CSV
    const content = formatAsCSV(auditResult.findings, options);

    // Generate Content-Disposition header
    const contentDisposition = getCSVContentDisposition(provider, domain);

    return {
      content,
      contentType: 'text/csv; charset=utf-8',
      contentDisposition,
    };
  }
}
