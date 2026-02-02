/**
 * CSV Formatter
 *
 * Formats audit results as CSV for export.
 * Story 1.9: Export Service
 *
 * CSV structure (flat table):
 * - Category
 * - Type
 * - Severity
 * - Count
 * - Title
 * - Description
 * - Affected Objects (optional)
 *
 * Excel-compatible: UTF-8 with BOM (Byte Order Mark)
 */

import { Finding } from '../../../types/finding.types';

/**
 * Export options for CSV formatter
 */
export interface CSVExportOptions {
  /**
   * Include affected entities column (default: false)
   */
  includeAffectedEntities?: boolean;

  /**
   * Column delimiter (default: ',')
   */
  delimiter?: string;
}

/**
 * Escape CSV value
 *
 * Rules:
 * - If value contains delimiter, double quote, or newline: wrap in double quotes
 * - Escape internal double quotes by doubling them (" -> "")
 *
 * @param value Value to escape
 * @param delimiter Column delimiter
 * @returns Escaped value
 */
function escapeCSVValue(value: string, delimiter: string): string {
  if (!value) return '';

  // Check if escaping is needed
  const needsEscaping = value.includes(delimiter) || value.includes('"') || value.includes('\n') || value.includes('\r');

  if (!needsEscaping) {
    return value;
  }

  // Escape internal double quotes by doubling them
  const escaped = value.replace(/"/g, '""');

  // Wrap in double quotes
  return `"${escaped}"`;
}

/**
 * Format audit findings as CSV
 *
 * @param findings Vulnerability findings
 * @param options Export options
 * @returns CSV string with UTF-8 BOM
 */
export function formatAsCSV(findings: Finding[], options: CSVExportOptions = {}): string {
  const { includeAffectedEntities = false, delimiter = ',' } = options;

  // Build CSV header
  const headers = ['Category', 'Type', 'Severity', 'Count', 'Title', 'Description'];
  if (includeAffectedEntities) {
    headers.push('Affected Objects');
  }

  const rows: string[] = [headers.join(delimiter)];

  // Build CSV rows
  findings.forEach((finding) => {
    const row = [
      escapeCSVValue(finding.category, delimiter),
      escapeCSVValue(finding.type, delimiter),
      escapeCSVValue(finding.severity, delimiter),
      String(finding.count),
      escapeCSVValue(finding.title, delimiter),
      escapeCSVValue(finding.description, delimiter),
    ];

    if (includeAffectedEntities) {
      const affectedObjects = finding.affectedEntities?.join('; ') || '';
      row.push(escapeCSVValue(affectedObjects, delimiter));
    }

    rows.push(row.join(delimiter));
  });

  const csvContent = rows.join('\n');

  // Add UTF-8 BOM for Excel compatibility
  // BOM: \uFEFF (EF BB BF in UTF-8)
  return '\uFEFF' + csvContent;
}

/**
 * Generate Content-Disposition header value for CSV export
 *
 * Format: `attachment; filename="audit-{provider}-{domain}-{timestamp}.csv"`
 * Example: `attachment; filename="audit-ad-EXAMPLE-2026-01-12T10-30-00Z.csv"`
 *
 * @param provider Provider type (ad or azure)
 * @param domain Domain name or tenant ID
 * @returns Content-Disposition header value
 */
export function getCSVContentDisposition(provider: string, domain: string): string {
  const timestamp = new Date().toISOString().replace(/:/g, '-').replace(/\..+/, 'Z');
  const sanitizedDomain = domain.replace(/[^a-zA-Z0-9-_]/g, '-');
  const filename = `audit-${provider}-${sanitizedDomain}-${timestamp}.csv`;

  return `attachment; filename="${filename}"`;
}
