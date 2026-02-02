/**
 * Unit Tests for Conditional Access Vulnerability Detector
 * Story 1.8: Azure Vulnerability Detection Engine
 *
 * Tests all Conditional Access policy-related vulnerability detectors (6 types):
 * - AZURE_NO_MFA_CA_POLICY
 * - AZURE_NO_LEGACY_AUTH_BLOCK
 * - AZURE_CA_POLICY_DISABLED
 * - AZURE_CA_POLICY_HAS_EXCLUSIONS
 * - AZURE_NO_DEVICE_COMPLIANCE_CA
 * - AZURE_CA_POLICY_REPORT_ONLY
 */

import {
  detectNoMfaCaPolicy,
  detectNoLegacyAuthBlock,
  detectCaPolicyDisabled,
  detectCaPolicyHasExclusions,
  detectNoDeviceComplianceCa,
  detectCaPolicyReportOnly,
  detectConditionalAccessVulnerabilities,
} from '../../../../../../src/services/audit/detectors/azure/conditional-access.detector';
import { AzurePolicy } from '../../../../../../src/types/azure.types';

describe('Conditional Access Detectors', () => {
  const createPolicy = (overrides: Partial<AzurePolicy> = {}): AzurePolicy => ({
    id: 'policy-123',
    displayName: 'Test Policy',
    state: 'enabled',
    ...overrides,
  });

  describe('detectNoMfaCaPolicy', () => {
    it('should detect absence of MFA policy', () => {
      const policies: AzurePolicy[] = [
        createPolicy({
          id: 'policy-1',
          state: 'enabled',
        } as any),
      ];

      // Policy without MFA requirement
      (policies[0] as any).grantControls = {
        builtInControls: ['block'],
      };

      const result = detectNoMfaCaPolicy(policies, false);

      expect(result.type).toBe('AZURE_NO_MFA_CA_POLICY');
      expect(result.severity).toBe('critical');
      expect(result.category).toBe('conditionalAccess');
      expect(result.count).toBe(1);
    });

    it('should not detect when MFA policy exists', () => {
      const policies: AzurePolicy[] = [
        createPolicy({
          id: 'policy-1',
          state: 'enabled',
        } as any),
      ];

      (policies[0] as any).grantControls = {
        builtInControls: ['mfa'],
      };

      const result = detectNoMfaCaPolicy(policies, false);

      expect(result.count).toBe(0);
    });

    it('should ignore disabled policies', () => {
      const policies: AzurePolicy[] = [
        createPolicy({
          id: 'policy-1',
          state: 'disabled',
        } as any),
      ];

      (policies[0] as any).grantControls = {
        builtInControls: ['mfa'],
      };

      const result = detectNoMfaCaPolicy(policies, false);

      expect(result.count).toBe(1); // MFA policy not found (disabled doesn't count)
    });
  });

  describe('detectNoLegacyAuthBlock', () => {
    it('should detect absence of legacy auth blocking', () => {
      const policies: AzurePolicy[] = [
        createPolicy({
          id: 'policy-1',
          state: 'enabled',
        } as any),
      ];

      (policies[0] as any).conditions = {
        clientAppTypes: ['browser', 'mobileAppsAndDesktopClients'],
      };

      const result = detectNoLegacyAuthBlock(policies, false);

      expect(result.type).toBe('AZURE_NO_LEGACY_AUTH_BLOCK');
      expect(result.severity).toBe('critical');
      expect(result.count).toBe(1);
    });

    it('should not detect when legacy auth is blocked', () => {
      const policies: AzurePolicy[] = [
        createPolicy({
          id: 'policy-1',
          state: 'enabled',
        } as any),
      ];

      (policies[0] as any).conditions = {
        clientAppTypes: ['exchangeActiveSync', 'other'],
      };
      (policies[0] as any).grantControls = {
        builtInControls: ['block'],
      };

      const result = detectNoLegacyAuthBlock(policies, false);

      expect(result.count).toBe(0);
    });
  });

  describe('detectCaPolicyDisabled', () => {
    it('should detect disabled policies', () => {
      const policies: AzurePolicy[] = [
        createPolicy({ id: 'policy-1', displayName: 'Disabled Policy', state: 'disabled' }),
        createPolicy({ id: 'policy-2', displayName: 'Enabled Policy', state: 'enabled' }),
      ];

      const result = detectCaPolicyDisabled(policies, false);

      expect(result.type).toBe('AZURE_CA_POLICY_DISABLED');
      expect(result.severity).toBe('medium');
      expect(result.count).toBe(1);
    });

    it('should include affected entities when includeDetails=true', () => {
      const policies: AzurePolicy[] = [
        createPolicy({ id: 'policy-1', displayName: 'Disabled MFA Policy', state: 'disabled' }),
      ];

      const result = detectCaPolicyDisabled(policies, true);

      expect(result.affectedEntities).toBeDefined();
      expect(result.affectedEntities).toContain('Disabled MFA Policy');
    });
  });

  describe('detectCaPolicyHasExclusions', () => {
    it('should detect policies with user exclusions', () => {
      const policies: AzurePolicy[] = [
        createPolicy({
          id: 'policy-1',
          state: 'enabled',
        } as any),
      ];

      (policies[0] as any).conditions = {
        users: {
          includeUsers: ['All'],
          excludeUsers: ['user-1', 'user-2'],
        },
      };

      const result = detectCaPolicyHasExclusions(policies, false);

      expect(result.type).toBe('AZURE_CA_POLICY_HAS_EXCLUSIONS');
      expect(result.severity).toBe('medium');
      expect(result.count).toBe(1);
    });

    it('should detect policies with group exclusions', () => {
      const policies: AzurePolicy[] = [
        createPolicy({
          id: 'policy-1',
          state: 'enabled',
        } as any),
      ];

      (policies[0] as any).conditions = {
        users: {
          includeUsers: ['All'],
          excludeGroups: ['group-1'],
        },
      };

      const result = detectCaPolicyHasExclusions(policies, false);

      expect(result.count).toBe(1);
    });

    it('should detect policies with role exclusions', () => {
      const policies: AzurePolicy[] = [
        createPolicy({
          id: 'policy-1',
          state: 'enabled',
        } as any),
      ];

      (policies[0] as any).conditions = {
        users: {
          includeUsers: ['All'],
          excludeRoles: ['role-1'],
        },
      };

      const result = detectCaPolicyHasExclusions(policies, false);

      expect(result.count).toBe(1);
    });

    it('should not detect policies without exclusions', () => {
      const policies: AzurePolicy[] = [
        createPolicy({
          id: 'policy-1',
          state: 'enabled',
        } as any),
      ];

      (policies[0] as any).conditions = {
        users: {
          includeUsers: ['All'],
        },
      };

      const result = detectCaPolicyHasExclusions(policies, false);

      expect(result.count).toBe(0);
    });
  });

  describe('detectNoDeviceComplianceCa', () => {
    it('should detect absence of device compliance requirement', () => {
      const policies: AzurePolicy[] = [
        createPolicy({
          id: 'policy-1',
          state: 'enabled',
        } as any),
      ];

      (policies[0] as any).grantControls = {
        builtInControls: ['mfa'],
      };

      const result = detectNoDeviceComplianceCa(policies, false);

      expect(result.type).toBe('AZURE_NO_DEVICE_COMPLIANCE_CA');
      expect(result.severity).toBe('medium');
      expect(result.count).toBe(1);
    });

    it('should not detect when compliant device is required', () => {
      const policies: AzurePolicy[] = [
        createPolicy({
          id: 'policy-1',
          state: 'enabled',
        } as any),
      ];

      (policies[0] as any).grantControls = {
        builtInControls: ['compliantDevice'],
      };

      const result = detectNoDeviceComplianceCa(policies, false);

      expect(result.count).toBe(0);
    });

    it('should not detect when domain joined device is required', () => {
      const policies: AzurePolicy[] = [
        createPolicy({
          id: 'policy-1',
          state: 'enabled',
        } as any),
      ];

      (policies[0] as any).grantControls = {
        builtInControls: ['domainJoinedDevice'],
      };

      const result = detectNoDeviceComplianceCa(policies, false);

      expect(result.count).toBe(0);
    });
  });

  describe('detectCaPolicyReportOnly', () => {
    it('should detect report-only policies', () => {
      const policies: AzurePolicy[] = [
        createPolicy({
          id: 'policy-1',
          displayName: 'Report Only Policy',
          state: 'enabledForReportingButNotEnforced',
        }),
        createPolicy({
          id: 'policy-2',
          displayName: 'Enforced Policy',
          state: 'enabled',
        }),
      ];

      const result = detectCaPolicyReportOnly(policies, false);

      expect(result.type).toBe('AZURE_CA_POLICY_REPORT_ONLY');
      expect(result.severity).toBe('low');
      expect(result.count).toBe(1);
    });
  });

  describe('detectConditionalAccessVulnerabilities', () => {
    it('should detect multiple CA vulnerabilities', () => {
      const policies: AzurePolicy[] = [
        createPolicy({
          id: 'policy-1',
          displayName: 'Disabled Policy',
          state: 'disabled',
        }),
        createPolicy({
          id: 'policy-2',
          displayName: 'Report Only',
          state: 'enabledForReportingButNotEnforced',
        }),
      ];

      const results = detectConditionalAccessVulnerabilities(policies, false);

      expect(results.length).toBeGreaterThan(0);
      const types = results.map((r) => r.type);
      expect(types).toContain('AZURE_CA_POLICY_DISABLED');
      expect(types).toContain('AZURE_CA_POLICY_REPORT_ONLY');
    });

    it('should handle empty policy list', () => {
      const results = detectConditionalAccessVulnerabilities([], false);

      // Should detect absence of critical policies
      expect(results.length).toBeGreaterThan(0);
      const types = results.map((r) => r.type);
      expect(types).toContain('AZURE_NO_MFA_CA_POLICY');
      expect(types).toContain('AZURE_NO_LEGACY_AUTH_BLOCK');
    });

    it('should filter out findings with count 0', () => {
      const policies: AzurePolicy[] = [
        createPolicy({
          id: 'policy-1',
          state: 'enabled',
        } as any),
      ];

      // Policy with MFA and device compliance
      (policies[0] as any).grantControls = {
        builtInControls: ['mfa', 'compliantDevice'],
      };
      (policies[0] as any).conditions = {
        clientAppTypes: ['exchangeActiveSync', 'other'],
      };

      const results = detectConditionalAccessVulnerabilities(policies, false);

      results.forEach((finding) => {
        expect(finding.count).toBeGreaterThan(0);
      });
    });
  });
});
