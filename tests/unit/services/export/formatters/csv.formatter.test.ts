/**
 * Unit Tests for CSV Formatter
 * Story 1.9: Export Service
 */

import {
  formatAsCSV,
  getCSVContentDisposition,
  CSVExportOptions,
} from '../../../../../src/services/export/formatters/csv.formatter';
import { Finding } from '../../../../../src/types/finding.types';

describe('CSV Formatter', () => {
  const mockFindings: Finding[] = [
    {
      type: 'PASSWORD_NOT_REQUIRED',
      severity: 'critical',
      category: 'passwords',
      title: 'Password Not Required',
      description: 'User account does not require a password',
      count: 5,
      affectedEntities: ['user1', 'user2', 'user3'],
    },
    {
      type: 'USER_INACTIVE',
      severity: 'high',
      category: 'accounts',
      title: 'Inactive User',
      description: 'User has not logged in for 90+ days',
      count: 10,
    },
    {
      type: 'PASSWORD_OLD',
      severity: 'medium',
      category: 'passwords',
      title: 'Old Password',
      description: 'Password not changed for 180+ days',
      count: 20,
      affectedEntities: ['olduser1'],
    },
  ];

  describe('formatAsCSV', () => {
    it('should format findings as CSV with header row', () => {
      const result = formatAsCSV(mockFindings);

      const lines = result.split('\n');
      expect(lines.length).toBeGreaterThan(1);

      // Check header (skip BOM)
      const header = lines[0]?.replace('\uFEFF', '') || '';
      expect(header).toBe('Category,Type,Severity,Count,Title,Description');
    });

    it('should include all findings as data rows', () => {
      const result = formatAsCSV(mockFindings);

      const lines = result.split('\n');
      expect(lines.length).toBe(4); // 1 header + 3 data rows
    });

    it('should format data row correctly', () => {
      const result = formatAsCSV(mockFindings);

      const lines = result.split('\n');
      const firstDataRow = lines[1];

      expect(firstDataRow).toContain('passwords');
      expect(firstDataRow).toContain('PASSWORD_NOT_REQUIRED');
      expect(firstDataRow).toContain('critical');
      expect(firstDataRow).toContain('5');
      expect(firstDataRow).toContain('Password Not Required');
    });

    it('should escape values containing commas', () => {
      const findings: Finding[] = [
        {
          type: 'TEST',
          severity: 'low',
          category: 'passwords',
          title: 'Test, with comma',
          description: 'Description, also with comma',
          count: 1,
        },
      ];

      const result = formatAsCSV(findings);

      expect(result).toContain('"Test, with comma"');
      expect(result).toContain('"Description, also with comma"');
    });

    it('should escape values containing double quotes', () => {
      const findings: Finding[] = [
        {
          type: 'TEST',
          severity: 'low',
          category: 'passwords',
          title: 'Test with "quotes"',
          description: 'Description with "quotes"',
          count: 1,
        },
      ];

      const result = formatAsCSV(findings);

      // Double quotes should be escaped as ""
      expect(result).toContain('"Test with ""quotes"""');
      expect(result).toContain('"Description with ""quotes"""');
    });

    it('should escape values containing newlines', () => {
      const findings: Finding[] = [
        {
          type: 'TEST',
          severity: 'low',
          category: 'passwords',
          title: 'Test\nwith newline',
          description: 'Description\nwith newline',
          count: 1,
        },
      ];

      const result = formatAsCSV(findings);

      expect(result).toContain('"Test\nwith newline"');
      expect(result).toContain('"Description\nwith newline"');
    });

    it('should not escape simple values', () => {
      const findings: Finding[] = [
        {
          type: 'SIMPLE_TEST',
          severity: 'low',
          category: 'passwords',
          title: 'Simple Title',
          description: 'Simple description without special characters',
          count: 1,
        },
      ];

      const result = formatAsCSV(findings);

      const lines = result.split('\n');
      const dataRow = lines[1];

      // Simple values should NOT be wrapped in quotes
      expect(dataRow).toContain('Simple Title');
      expect(dataRow).not.toContain('"Simple Title"');
    });

    it('should include UTF-8 BOM for Excel compatibility', () => {
      const result = formatAsCSV(mockFindings);

      // Check for BOM character at start
      expect(result.charCodeAt(0)).toBe(0xfeff);
    });

    it('should include Affected Objects column when includeAffectedEntities=true', () => {
      const options: CSVExportOptions = {
        includeAffectedEntities: true,
      };

      const result = formatAsCSV(mockFindings, options);

      const lines = result.split('\n');
      const header = lines[0]?.replace('\uFEFF', '');

      expect(header).toBe('Category,Type,Severity,Count,Title,Description,Affected Objects');
    });

    it('should include affected entities in data rows when enabled', () => {
      const options: CSVExportOptions = {
        includeAffectedEntities: true,
      };

      const result = formatAsCSV(mockFindings, options);

      const lines = result.split('\n');
      const firstDataRow = lines[1];

      // Should contain semicolon-separated list
      expect(firstDataRow).toContain('user1; user2; user3');
    });

    it('should handle missing affectedEntities gracefully', () => {
      const options: CSVExportOptions = {
        includeAffectedEntities: true,
      };

      const result = formatAsCSV(mockFindings, options);

      const lines = result.split('\n');
      const secondDataRow = lines[2] || '';

      // USER_INACTIVE has no affectedEntities
      expect(secondDataRow.split(',').length).toBe(7); // All 7 columns present
    });

    it('should use custom delimiter when provided', () => {
      const options: CSVExportOptions = {
        delimiter: ';',
      };

      const result = formatAsCSV(mockFindings, options);

      const lines = result.split('\n');
      const header = lines[0]?.replace('\uFEFF', '');

      expect(header).toBe('Category;Type;Severity;Count;Title;Description');
    });

    it('should handle empty findings array', () => {
      const result = formatAsCSV([]);

      const lines = result.split('\n');
      expect(lines.length).toBe(1); // Only header
    });

    it('should handle findings with empty descriptions', () => {
      const findings: Finding[] = [
        {
          type: 'TEST',
          severity: 'low',
          category: 'passwords',
          title: 'Test',
          description: '',
          count: 1,
        },
      ];

      const result = formatAsCSV(findings);

      expect(() => result.split('\n')).not.toThrow();
      expect(result.split('\n').length).toBe(2); // Header + 1 data row
    });
  });

  describe('getCSVContentDisposition', () => {
    it('should generate correct Content-Disposition header', () => {
      const result = getCSVContentDisposition('ad', 'EXAMPLE');

      expect(result).toContain('attachment');
      expect(result).toContain('filename="audit-ad-EXAMPLE-');
      expect(result).toContain('.csv"');
    });

    it('should sanitize domain name', () => {
      const result = getCSVContentDisposition('ad', 'example.local@test');

      // Domain should be sanitized (no dots or @)
      expect(result).toContain('audit-ad-example-local-test-');
      // Should not contain the original domain with dots/@ (but .csv extension is ok)
      expect(result).not.toContain('example.local@test');
    });

    it('should include timestamp in ISO format', () => {
      const result = getCSVContentDisposition('ad', 'EXAMPLE');

      // Should contain timestamp like 2026-01-12T10-30-00Z
      expect(result).toMatch(/\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}Z\.csv"/);
    });

    it('should work with Azure provider', () => {
      const result = getCSVContentDisposition('azure', 'tenant-123');

      expect(result).toContain('audit-azure-tenant-123-');
    });
  });
});
