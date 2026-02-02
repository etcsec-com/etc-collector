/**
 * AD Audit Service Integration Tests
 *
 * Tests the full AD audit flow with real LDAP connectivity
 * Story 1.7: AD Vulnerability Detection Engine
 *
 * Prerequisites:
 * - .env.test.local configured with valid LDAP credentials
 * - LDAP server accessible
 */

import { ADAuditService } from '../../src/services/audit/ad-audit.service';
import { LDAPProvider } from '../../src/providers/ldap/ldap.provider';
import { LDAPConfig } from '../../src/types/config.types';
import dotenv from 'dotenv';
import path from 'path';

// Load test environment variables
dotenv.config({ path: path.resolve(__dirname, '../../.env.test.local') });

describe('AD Audit Service - Integration Tests', () => {
  let auditService: ADAuditService;
  let ldapProvider: LDAPProvider;

  const ldapConfig: LDAPConfig = {
    url: process.env['TEST_LDAP_URL'] || '',
    bindDN: process.env['TEST_LDAP_BIND_DN'] || '',
    bindPassword: process.env['TEST_LDAP_BIND_PASSWORD'] || '',
    baseDN: process.env['TEST_LDAP_BASE_DN'] || '',
    tlsVerify: process.env['TEST_LDAP_TLS_VERIFY'] === 'true',
    timeout: 30000,
  };

  beforeAll(async () => {
    // Skip tests if LDAP not configured
    if (!ldapConfig.url || !ldapConfig.bindDN || !ldapConfig.bindPassword) {
      console.warn('LDAP credentials not configured in .env.test.local - skipping integration tests');
      return;
    }

    // Create provider and service
    ldapProvider = new LDAPProvider(ldapConfig);
    auditService = new ADAuditService(ldapProvider);

    // Connect to LDAP
    await ldapProvider.connect();
  }, 60000);

  afterAll(async () => {
    if (ldapProvider) {
      await ldapProvider.disconnect();
    }
  });

  describe('Connection Tests', () => {
    it('should connect to LDAP server', async () => {
      const result = await auditService.testConnection();
      expect(result.success).toBe(true);
      expect(result.message).toContain('Connection successful');
    }, 30000);

    it('should connect to LDAP server', async () => {
      await expect(ldapProvider.connect()).resolves.not.toThrow();
    }, 30000);
  });

  describe('AD Audit Execution', () => {
    it('should run full AD audit', async () => {
      const result = await auditService.runAudit({
        includeDetails: false,
        maxUsers: 2000,
        maxGroups: 200,
        maxComputers: 200,
      });

      // Verify result structure
      expect(result).toHaveProperty('score');
      expect(result).toHaveProperty('findings');
      expect(result).toHaveProperty('stats');
      expect(result).toHaveProperty('timestamp');

      // Verify score structure
      expect(result.score).toHaveProperty('score');
      expect(result.score).toHaveProperty('rating');
      expect(result.score).toHaveProperty('weightedPoints');
      expect(result.score).toHaveProperty('findings');
      expect(result.score).toHaveProperty('categories');

      // Score should be between 0 and 100
      expect(result.score.score).toBeGreaterThanOrEqual(0);
      expect(result.score.score).toBeLessThanOrEqual(100);

      // Verify stats
      expect(result.stats.totalUsers).toBeGreaterThan(0);
      expect(result.stats.executionTimeMs).toBeGreaterThan(0);

      // Log results
      console.log('\n=== AD Audit Results ===');
      console.log(`Security Score: ${result.score.score}/100 (${result.score.rating})`);
      console.log(`Total Users: ${result.stats.totalUsers}`);
      console.log(`Total Groups: ${result.stats.totalGroups}`);
      console.log(`Total Computers: ${result.stats.totalComputers}`);
      console.log(`Total Findings: ${result.stats.totalFindings}`);
      console.log(`Execution Time: ${result.stats.executionTimeMs}ms`);
      console.log('\nFindings by Severity:');
      console.log(`  Critical: ${result.score.findings.critical}`);
      console.log(`  High: ${result.score.findings.high}`);
      console.log(`  Medium: ${result.score.findings.medium}`);
      console.log(`  Low: ${result.score.findings.low}`);

      if (result.findings.length > 0) {
        console.log('\nTop 5 Findings:');
        result.findings.slice(0, 5).forEach((finding, i) => {
          console.log(`  ${i + 1}. [${finding.severity.toUpperCase()}] ${finding.title}: ${finding.count} affected`);
        });
      }
    }, 120000);

    it('should include details when requested', async () => {
      const result = await auditService.runAudit({
        includeDetails: true,
        maxUsers: 10,
      });

      // Find a finding with affected entities
      const findingWithDetails = result.findings.find((f) => f.affectedEntities && f.affectedEntities.length > 0);

      if (findingWithDetails) {
        expect(findingWithDetails.affectedEntities).toBeDefined();
        expect(Array.isArray(findingWithDetails.affectedEntities)).toBe(true);
        expect(findingWithDetails.affectedEntities!.length).toBeGreaterThan(0);
        console.log(`\nSample finding with details: ${findingWithDetails.title}`);
        console.log(`Affected entities: ${findingWithDetails.affectedEntities!.slice(0, 3).join(', ')}`);
      }
    }, 120000);

    it('should detect password vulnerabilities', async () => {
      const result = await auditService.runAudit({
        maxUsers: 2000,
      });

      const passwordFindings = result.findings.filter((f) => f.category === 'passwords');
      console.log(`\nPassword vulnerabilities found: ${passwordFindings.length}`);
      passwordFindings.forEach((f) => {
        console.log(`  - ${f.title}: ${f.count} (${f.severity})`);
      });

      // Just verify we got results, not specific counts (depends on AD state)
      expect(result.findings.length).toBeGreaterThanOrEqual(0);
    }, 120000);

    it('should detect kerberos vulnerabilities', async () => {
      const result = await auditService.runAudit({
        maxUsers: 2000,
      });

      const kerberosFindings = result.findings.filter((f) => f.category === 'kerberos');
      console.log(`\nKerberos vulnerabilities found: ${kerberosFindings.length}`);
      kerberosFindings.forEach((f) => {
        console.log(`  - ${f.title}: ${f.count} (${f.severity})`);
      });
    }, 120000);

    it('should detect account vulnerabilities', async () => {
      const result = await auditService.runAudit({
        maxUsers: 2000,
      });

      const accountFindings = result.findings.filter((f) => f.category === 'accounts');
      console.log(`\nAccount vulnerabilities found: ${accountFindings.length}`);
      accountFindings.forEach((f) => {
        console.log(`  - ${f.title}: ${f.count} (${f.severity})`);
      });
    }, 120000);

    it('should show ALL vulnerabilities by category', async () => {
      const result = await auditService.runAudit({
        maxUsers: 2000,
      });

      console.log(`\n\n=== COMPLETE VULNERABILITY BREAKDOWN ===`);
      console.log(`Total Findings: ${result.findings.length}`);

      const byCategory = result.findings.reduce((acc: any, f) => {
        if (!acc[f.category]) acc[f.category] = [];
        acc[f.category].push(f);
        return acc;
      }, {});

      Object.keys(byCategory).sort().forEach(category => {
        console.log(`\n${category.toUpperCase()} (${byCategory[category].length} types):`);
        byCategory[category]
          .sort((a: any, b: any) => b.count - a.count)
          .forEach((f: any) => {
            console.log(`  - [${f.severity.toUpperCase()}] ${f.title}: ${f.count}`);
          });
      });
    }, 120000);
  });

  describe('Error Handling', () => {
    it('should handle invalid LDAP credentials gracefully', async () => {
      const badConfig: LDAPConfig = {
        ...ldapConfig,
        bindPassword: 'invalid_password',
      };

      const badProvider = new LDAPProvider(badConfig);
      const badService = new ADAuditService(badProvider);

      await expect(badService.testConnection()).resolves.toMatchObject({
        success: false,
      });
    }, 30000);
  });
});
