/**
 * Unit Tests for JSON Formatter
 * Story 1.9: Export Service
 */

import {
  formatAsJSON,
  getJSONContentDisposition,
  JSONExportOptions,
  JSONExportResult,
} from '../../../../../src/services/export/formatters/json.formatter';
import { Finding } from '../../../../../src/types/finding.types';
import { SecurityScore } from '../../../../../src/services/audit/scoring.service';

describe('JSON Formatter', () => {
  const mockScore: SecurityScore = {
    score: 75.5,
    rating: 'good',
    weightedPoints: 100,
    totalUsers: 1000,
    findings: {
      critical: 5,
      high: 10,
      medium: 20,
      low: 5,
      total: 40,
    },
    categories: {
      passwords: 25,
      kerberos: 5,
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
      affectedEntities: ['user1', 'user2', 'user3', 'user4', 'user5'],
    },
    {
      type: 'USER_INACTIVE',
      severity: 'high',
      category: 'accounts',
      title: 'Inactive User Account',
      description: 'User has not logged in for 90+ days',
      count: 10,
      affectedEntities: ['inactive1', 'inactive2'],
    },
    {
      type: 'PASSWORD_OLD',
      severity: 'medium',
      category: 'passwords',
      title: 'Old Password',
      description: 'Password not changed for 180+ days',
      count: 20,
    },
  ];

  const mockStats = {
    totalUsers: 1000,
    totalGroups: 50,
    totalComputers: 100,
    executionTimeMs: 5000,
  };

  describe('formatAsJSON', () => {
    it('should format audit results as valid JSON', () => {
      const options: JSONExportOptions = {
        provider: 'ad',
        domain: 'example.com',
      };

      const result = formatAsJSON(mockScore, mockFindings, mockStats, options);

      expect(result).toBeTruthy();
      expect(() => JSON.parse(result)).not.toThrow();
    });

    it('should include metadata section', () => {
      const options: JSONExportOptions = {
        provider: 'ad',
        domain: 'example.com',
      };

      const result = formatAsJSON(mockScore, mockFindings, mockStats, options);
      const parsed: JSONExportResult = JSON.parse(result);

      expect(parsed.metadata).toBeDefined();
      expect(parsed.metadata.provider).toBe('ad');
      expect(parsed.metadata.domain).toBe('example.com');
      expect(parsed.metadata.executionTimeMs).toBe(5000);
      expect(parsed.metadata.version).toBe('1.0.0');
      expect(parsed.metadata.timestamp).toBeDefined();
    });

    it('should include summary section with score and breakdowns', () => {
      const options: JSONExportOptions = {
        provider: 'ad',
        domain: 'example.com',
      };

      const result = formatAsJSON(mockScore, mockFindings, mockStats, options);
      const parsed: JSONExportResult = JSON.parse(result);

      expect(parsed.summary).toBeDefined();
      expect(parsed.summary.score).toEqual(mockScore);
      expect(parsed.summary.totalFindings).toBe(35); // 5 + 10 + 20

      expect(parsed.summary.severityBreakdown).toEqual({
        critical: 5,
        high: 10,
        medium: 20,
        low: 0,
      });

      expect(parsed.summary.categoryBreakdown).toEqual({
        passwords: 25, // 5 + 20
        accounts: 10,
      });
    });

    it('should include findings without affectedEntities by default', () => {
      const options: JSONExportOptions = {
        provider: 'ad',
        domain: 'example.com',
      };

      const result = formatAsJSON(mockScore, mockFindings, mockStats, options);
      const parsed: JSONExportResult = JSON.parse(result);

      expect(parsed.findings).toBeDefined();
      expect(parsed.findings.length).toBe(3);
      expect(parsed.findings[0]?.affectedEntities).toBeUndefined();
      expect(parsed.findings[0]?.type).toBe('PASSWORD_NOT_REQUIRED');
      expect(parsed.findings[0]?.count).toBe(5);
    });

    it('should include affectedEntities when includeDetails=true', () => {
      const options: JSONExportOptions = {
        provider: 'ad',
        domain: 'example.com',
        includeDetails: true,
      };

      const result = formatAsJSON(mockScore, mockFindings, mockStats, options);
      const parsed: JSONExportResult = JSON.parse(result);

      expect(parsed.findings[0]?.affectedEntities).toBeDefined();
      expect(parsed.findings[0]?.affectedEntities).toHaveLength(5);
      expect(parsed.findings[0]?.affectedEntities).toContain('user1');
    });

    it('should include stats section', () => {
      const options: JSONExportOptions = {
        provider: 'ad',
        domain: 'example.com',
      };

      const result = formatAsJSON(mockScore, mockFindings, mockStats, options);
      const parsed: JSONExportResult = JSON.parse(result);

      expect(parsed.stats).toBeDefined();
      expect(parsed.stats.totalUsers).toBe(1000);
      expect(parsed.stats.totalGroups).toBe(50);
      expect(parsed.stats.totalComputers).toBe(100);
    });

    it('should handle Azure provider with tenantId', () => {
      const options: JSONExportOptions = {
        provider: 'azure',
        tenantId: 'tenant-123-456',
      };

      const result = formatAsJSON(mockScore, mockFindings, mockStats, options);
      const parsed: JSONExportResult = JSON.parse(result);

      expect(parsed.metadata.provider).toBe('azure');
      expect(parsed.metadata.tenantId).toBe('tenant-123-456');
    });

    it('should handle empty findings array', () => {
      const options: JSONExportOptions = {
        provider: 'ad',
        domain: 'example.com',
      };

      const result = formatAsJSON(mockScore, [], mockStats, options);
      const parsed: JSONExportResult = JSON.parse(result);

      expect(parsed.findings).toEqual([]);
      expect(parsed.summary.totalFindings).toBe(0);
      expect(parsed.summary.severityBreakdown).toEqual({
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
      });
    });

    it('should pretty-print JSON with 2-space indentation', () => {
      const options: JSONExportOptions = {
        provider: 'ad',
        domain: 'example.com',
      };

      const result = formatAsJSON(mockScore, mockFindings, mockStats, options);

      expect(result).toContain('\n  '); // Check for indentation
      expect(result).toContain('"metadata"');
    });
  });

  describe('getJSONContentDisposition', () => {
    it('should generate correct Content-Disposition header', () => {
      const result = getJSONContentDisposition('ad', 'EXAMPLE');

      expect(result).toContain('attachment');
      expect(result).toContain('filename="audit-ad-EXAMPLE-');
      expect(result).toContain('.json"');
    });

    it('should sanitize domain name', () => {
      const result = getJSONContentDisposition('ad', 'example.local@test');

      // Domain should be sanitized (no dots or @)
      expect(result).toContain('audit-ad-example-local-test-');
      // Should not contain the original domain with dots/@ (but .json extension is ok)
      expect(result).not.toContain('example.local@test');
    });

    it('should include timestamp in ISO format', () => {
      const result = getJSONContentDisposition('ad', 'EXAMPLE');

      // Should contain timestamp like 2026-01-12T10-30-00Z
      expect(result).toMatch(/\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}Z\.json"/);
    });

    it('should work with Azure provider', () => {
      const result = getJSONContentDisposition('azure', 'tenant-123');

      expect(result).toContain('audit-azure-tenant-123-');
    });
  });
});
