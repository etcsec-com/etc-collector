/**
 * Unit Tests for Export Service
 * Story 1.9: Export Service
 */

import { ExportService, ExportAuditResult } from '../../../../src/services/export/export.service';
import { Finding } from '../../../../src/types/finding.types';
import { SecurityScore } from '../../../../src/services/audit/scoring.service';

describe('ExportService', () => {
  let exportService: ExportService;

  const mockScore: SecurityScore = {
    score: 75.5,
    rating: 'good',
    weightedPoints: 100,
    totalUsers: 1000,
    findings: {
      critical: 5,
      high: 10,
      medium: 0,
      low: 0,
      total: 15,
    },
    categories: {
      passwords: 5,
      kerberos: 0,
      accounts: 10,
      groups: 0,
      computers: 0,
      advanced: 0,
      permissions: 0,
      config: 0,
      identity: 0,
      applications: 0,
      conditionalAccess: 0,
      privilegedAccess: 0,
    },
  };

  const mockFindings: Finding[] = [
    {
      type: 'PASSWORD_NOT_REQUIRED',
      severity: 'critical',
      category: 'passwords',
      title: 'Password Not Required',
      description: 'User account does not require a password',
      count: 5,
      affectedEntities: ['user1', 'user2'],
    },
    {
      type: 'USER_INACTIVE',
      severity: 'high',
      category: 'accounts',
      title: 'Inactive User',
      description: 'User has not logged in for 90+ days',
      count: 10,
    },
  ];

  const mockAuditResult: ExportAuditResult = {
    score: mockScore,
    findings: mockFindings,
    stats: {
      totalUsers: 1000,
      totalGroups: 50,
      totalComputers: 100,
      totalFindings: 15,
      executionTimeMs: 5000,
    },
    timestamp: new Date('2026-01-12T10:30:00Z'),
  };

  beforeEach(() => {
    exportService = new ExportService();
  });

  describe('exportToJSON', () => {
    it('should export audit result as JSON', () => {
      const result = exportService.exportToJSON(mockAuditResult, {
        provider: 'ad',
        domain: 'example.com',
      });

      expect(result).toBeDefined();
      expect(result.content).toBeDefined();
      expect(result.contentType).toBe('application/json; charset=utf-8');
      expect(result.contentDisposition).toContain('attachment');
    });

    it('should produce valid JSON', () => {
      const result = exportService.exportToJSON(mockAuditResult, {
        provider: 'ad',
        domain: 'example.com',
      });

      expect(() => JSON.parse(result.content)).not.toThrow();
    });

    it('should include correct Content-Disposition header', () => {
      const result = exportService.exportToJSON(mockAuditResult, {
        provider: 'ad',
        domain: 'EXAMPLE',
      });

      expect(result.contentDisposition).toContain('filename="audit-ad-EXAMPLE-');
      expect(result.contentDisposition).toContain('.json"');
    });

    it('should handle Azure provider', () => {
      const result = exportService.exportToJSON(mockAuditResult, {
        provider: 'azure',
        tenantId: 'tenant-123',
      });

      const parsed = JSON.parse(result.content);
      expect(parsed.metadata.provider).toBe('azure');
      expect(parsed.metadata.tenantId).toBe('tenant-123');
    });

    it('should exclude affectedEntities by default', () => {
      const result = exportService.exportToJSON(mockAuditResult, {
        provider: 'ad',
        domain: 'example.com',
      });

      const parsed = JSON.parse(result.content);
      expect(parsed.findings[0].affectedEntities).toBeUndefined();
    });

    it('should include affectedEntities when includeDetails=true', () => {
      const result = exportService.exportToJSON(mockAuditResult, {
        provider: 'ad',
        domain: 'example.com',
        includeDetails: true,
      });

      const parsed = JSON.parse(result.content);
      expect(parsed.findings[0].affectedEntities).toBeDefined();
      expect(parsed.findings[0].affectedEntities).toHaveLength(2);
    });

    it('should use tenantId as domain fallback', () => {
      const result = exportService.exportToJSON(mockAuditResult, {
        provider: 'azure',
        tenantId: 'tenant-123',
      });

      expect(result.contentDisposition).toContain('tenant-123');
    });

    it('should use "unknown" as domain when neither domain nor tenantId provided', () => {
      const result = exportService.exportToJSON(mockAuditResult, {
        provider: 'ad',
      });

      expect(result.contentDisposition).toContain('unknown');
    });
  });

  describe('exportToCSV', () => {
    it('should export audit result as CSV', () => {
      const result = exportService.exportToCSV(mockAuditResult, 'ad', 'example.com');

      expect(result).toBeDefined();
      expect(result.content).toBeDefined();
      expect(result.contentType).toBe('text/csv; charset=utf-8');
      expect(result.contentDisposition).toContain('attachment');
    });

    it('should include CSV header row', () => {
      const result = exportService.exportToCSV(mockAuditResult, 'ad', 'example.com');

      const lines = result.content.split('\n');
      const header = lines[0]?.replace('\uFEFF', '');

      expect(header).toBe('Category,Type,Severity,Count,Title,Description');
    });

    it('should include all findings as data rows', () => {
      const result = exportService.exportToCSV(mockAuditResult, 'ad', 'example.com');

      const lines = result.content.split('\n');
      expect(lines.length).toBe(3); // 1 header + 2 data rows
    });

    it('should include UTF-8 BOM', () => {
      const result = exportService.exportToCSV(mockAuditResult, 'ad', 'example.com');

      expect(result.content.charCodeAt(0)).toBe(0xfeff);
    });

    it('should include correct Content-Disposition header', () => {
      const result = exportService.exportToCSV(mockAuditResult, 'ad', 'EXAMPLE');

      expect(result.contentDisposition).toContain('filename="audit-ad-EXAMPLE-');
      expect(result.contentDisposition).toContain('.csv"');
    });

    it('should include Affected Objects column when option enabled', () => {
      const result = exportService.exportToCSV(mockAuditResult, 'ad', 'example.com', {
        includeAffectedEntities: true,
      });

      const lines = result.content.split('\n');
      const header = lines[0]?.replace('\uFEFF', '');

      expect(header).toContain('Affected Objects');
    });

    it('should use custom delimiter when provided', () => {
      const result = exportService.exportToCSV(mockAuditResult, 'ad', 'example.com', {
        delimiter: ';',
      });

      const lines = result.content.split('\n');
      const header = lines[0]?.replace('\uFEFF', '');

      expect(header).toContain(';');
      expect(header).not.toContain(',');
    });

    it('should handle Azure provider', () => {
      const result = exportService.exportToCSV(mockAuditResult, 'azure', 'tenant-123');

      expect(result.contentDisposition).toContain('audit-azure-tenant-123-');
    });

    it('should handle empty findings array', () => {
      const emptyAuditResult: ExportAuditResult = {
        ...mockAuditResult,
        findings: [],
      };

      const result = exportService.exportToCSV(emptyAuditResult, 'ad', 'example.com');

      const lines = result.content.split('\n');
      expect(lines.length).toBe(1); // Only header
    });
  });
});
