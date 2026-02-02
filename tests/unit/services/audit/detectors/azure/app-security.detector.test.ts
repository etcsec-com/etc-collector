/**
 * Unit Tests for App Security Vulnerability Detector
 * Story 1.8: Azure Vulnerability Detection Engine
 *
 * Tests all application-related vulnerability detectors (7 types):
 * - AZURE_APP_EXCESSIVE_GRAPH_PERMS
 * - AZURE_APP_CREDENTIAL_EXPIRED
 * - AZURE_APP_LONG_LIVED_CREDS
 * - AZURE_APP_MULTITENANT_UNVERIFIED
 * - AZURE_APP_CREDENTIAL_EXPIRING
 * - AZURE_SP_DISABLED_WITH_CREDS
 * - AZURE_APP_NO_OWNER
 */

import {
  detectAppExcessiveGraphPerms,
  detectAppCredentialExpired,
  detectAppLongLivedCreds,
  detectAppMultitenantUnverified,
  detectAppCredentialExpiring,
  detectSpDisabledWithCreds,
  detectAppNoOwner,
  detectAppSecurityVulnerabilities,
} from '../../../../../../src/services/audit/detectors/azure/app-security.detector';
import { AzureApp } from '../../../../../../src/types/azure.types';

describe('App Security Detectors', () => {
  const createApp = (overrides: Partial<AzureApp> = {}): AzureApp => ({
    id: 'app-123',
    appId: 'app-guid-123',
    displayName: 'Test App',
    createdDateTime: new Date().toISOString(),
    ...overrides,
  });

  const MICROSOFT_GRAPH_RESOURCE_ID = '00000003-0000-0000-c000-000000000000';

  describe('detectAppExcessiveGraphPerms', () => {
    it('should detect excessive Microsoft Graph permissions', () => {
      const apps: AzureApp[] = [
        createApp({
          id: 'app-1',
        } as any),
        createApp({ id: 'app-2' }),
      ];

      (apps[0] as any).requiredResourceAccess = [
        {
          resourceAppId: MICROSOFT_GRAPH_RESOURCE_ID,
          resourceAccess: [
            {
              id: '1bfefb4e-e0b5-418b-a88f-73c46d1986e9', // Directory.ReadWrite.All
              type: 'Role',
            },
          ],
        },
      ];

      const result = detectAppExcessiveGraphPerms(apps, false);

      expect(result.type).toBe('AZURE_APP_EXCESSIVE_GRAPH_PERMS');
      expect(result.severity).toBe('critical');
      expect(result.category).toBe('applications');
      expect(result.count).toBe(1);
    });

    it('should not detect apps without dangerous permissions', () => {
      const apps: AzureApp[] = [
        createApp({
          id: 'app-1',
        } as any),
      ];

      (apps[0] as any).requiredResourceAccess = [
        {
          resourceAppId: MICROSOFT_GRAPH_RESOURCE_ID,
          resourceAccess: [
            {
              id: 'e1fe6dd8-ba31-4d61-89e7-88639da4683d', // User.Read
              type: 'Scope',
            },
          ],
        },
      ];

      const result = detectAppExcessiveGraphPerms(apps, false);

      expect(result.count).toBe(0);
    });
  });

  describe('detectAppCredentialExpired', () => {
    it('should detect apps with expired credentials', () => {
      const now = Date.now();
      const yesterday = new Date(now - 24 * 60 * 60 * 1000).toISOString();

      const apps: AzureApp[] = [
        createApp({ id: 'app-1' } as any),
        createApp({ id: 'app-2' }),
      ];

      (apps[0] as any).passwordCredentials = [
        {
          displayName: 'Secret1',
          endDateTime: yesterday,
        },
      ];

      const result = detectAppCredentialExpired(apps, false);

      expect(result.type).toBe('AZURE_APP_CREDENTIAL_EXPIRED');
      expect(result.severity).toBe('high');
      expect(result.count).toBe(1);
    });

    it('should handle key credentials', () => {
      const now = Date.now();
      const yesterday = new Date(now - 24 * 60 * 60 * 1000).toISOString();

      const apps: AzureApp[] = [
        createApp({ id: 'app-1' } as any),
      ];

      (apps[0] as any).keyCredentials = [
        {
          displayName: 'Cert1',
          endDateTime: yesterday,
        },
      ];

      const result = detectAppCredentialExpired(apps, false);

      expect(result.count).toBe(1);
    });
  });

  describe('detectAppLongLivedCreds', () => {
    it('should detect long-lived credentials (>1 year)', () => {
      const now = Date.now();
      const twoYearsFromNow = new Date(now + 2 * 365 * 24 * 60 * 60 * 1000).toISOString();

      const apps: AzureApp[] = [
        createApp({ id: 'app-1' } as any),
        createApp({ id: 'app-2' }),
      ];

      (apps[0] as any).passwordCredentials = [
        {
          displayName: 'LongLived',
          endDateTime: twoYearsFromNow,
        },
      ];

      const result = detectAppLongLivedCreds(apps, false);

      expect(result.type).toBe('AZURE_APP_LONG_LIVED_CREDS');
      expect(result.severity).toBe('high');
      expect(result.count).toBe(1);
    });

    it('should not detect credentials <1 year', () => {
      const now = Date.now();
      const sixMonthsFromNow = new Date(now + 180 * 24 * 60 * 60 * 1000).toISOString();

      const apps: AzureApp[] = [
        createApp({ id: 'app-1' } as any),
      ];

      (apps[0] as any).passwordCredentials = [
        {
          displayName: 'ShortLived',
          endDateTime: sixMonthsFromNow,
        },
      ];

      const result = detectAppLongLivedCreds(apps, false);

      expect(result.count).toBe(0);
    });
  });

  describe('detectAppMultitenantUnverified', () => {
    it('should detect unverified multi-tenant apps', () => {
      const apps: AzureApp[] = [
        createApp({
          id: 'app-1',
          signInAudience: 'AzureADMultipleOrgs',
        } as any),
        createApp({
          id: 'app-2',
          signInAudience: 'AzureADMyOrg',
        }),
      ];

      // app-1 is multi-tenant but not verified
      (apps[0] as any).publisherDomain = null;

      const result = detectAppMultitenantUnverified(apps, false);

      expect(result.type).toBe('AZURE_APP_MULTITENANT_UNVERIFIED');
      expect(result.severity).toBe('high');
      expect(result.count).toBe(1);
    });

    it('should not detect verified multi-tenant apps', () => {
      const apps: AzureApp[] = [
        createApp({
          id: 'app-1',
          signInAudience: 'AzureADMultipleOrgs',
        } as any),
      ];

      (apps[0] as any).publisherDomain = 'verified.com';
      (apps[0] as any).verifiedPublisher = { displayName: 'Verified Publisher' };

      const result = detectAppMultitenantUnverified(apps, false);

      expect(result.count).toBe(0);
    });
  });

  describe('detectAppCredentialExpiring', () => {
    it('should detect credentials expiring within 30 days', () => {
      const now = Date.now();
      const twentyDaysFromNow = new Date(now + 20 * 24 * 60 * 60 * 1000).toISOString();

      const apps: AzureApp[] = [
        createApp({ id: 'app-1' } as any),
      ];

      (apps[0] as any).passwordCredentials = [
        {
          displayName: 'Expiring',
          endDateTime: twentyDaysFromNow,
        },
      ];

      const result = detectAppCredentialExpiring(apps, false);

      expect(result.type).toBe('AZURE_APP_CREDENTIAL_EXPIRING');
      expect(result.severity).toBe('medium');
      expect(result.count).toBe(1);
    });

    it('should not detect credentials expiring >30 days', () => {
      const now = Date.now();
      const fortyDaysFromNow = new Date(now + 40 * 24 * 60 * 60 * 1000).toISOString();

      const apps: AzureApp[] = [
        createApp({ id: 'app-1' } as any),
      ];

      (apps[0] as any).passwordCredentials = [
        {
          displayName: 'NotExpiringSoon',
          endDateTime: fortyDaysFromNow,
        },
      ];

      const result = detectAppCredentialExpiring(apps, false);

      expect(result.count).toBe(0);
    });
  });

  describe('detectSpDisabledWithCreds', () => {
    it('should detect disabled service principals with credentials', () => {
      const apps: AzureApp[] = [
        createApp({ id: 'sp-1' } as any),
        createApp({ id: 'sp-2' } as any),
      ];

      (apps[0] as any).accountEnabled = false;
      (apps[0] as any).passwordCredentials = [{ displayName: 'Secret' }];

      (apps[1] as any).accountEnabled = true;
      (apps[1] as any).passwordCredentials = [{ displayName: 'Secret' }];

      const result = detectSpDisabledWithCreds(apps, false);

      expect(result.type).toBe('AZURE_SP_DISABLED_WITH_CREDS');
      expect(result.severity).toBe('medium');
      expect(result.count).toBe(1);
    });
  });

  describe('detectAppNoOwner', () => {
    it('should detect apps without owners', () => {
      const apps: AzureApp[] = [
        createApp({ id: 'app-1' } as any),
        createApp({ id: 'app-2' } as any),
      ];

      (apps[0] as any).owners = [];
      (apps[1] as any).owners = [{ id: 'owner-1' }];

      const result = detectAppNoOwner(apps, false);

      expect(result.type).toBe('AZURE_APP_NO_OWNER');
      expect(result.severity).toBe('medium');
      expect(result.count).toBe(1);
    });
  });

  describe('detectAppSecurityVulnerabilities', () => {
    it('should detect multiple app vulnerabilities', () => {
      const now = Date.now();
      const yesterday = new Date(now - 24 * 60 * 60 * 1000).toISOString();

      const apps: AzureApp[] = [
        createApp({ id: 'app-1' } as any),
      ];

      (apps[0] as any).passwordCredentials = [
        {
          displayName: 'Expired',
          endDateTime: yesterday,
        },
      ];
      (apps[0] as any).owners = [];

      const results = detectAppSecurityVulnerabilities(apps, false);

      expect(results.length).toBeGreaterThan(0);
      const types = results.map((r) => r.type);
      expect(types).toContain('AZURE_APP_CREDENTIAL_EXPIRED');
      expect(types).toContain('AZURE_APP_NO_OWNER');
    });

    it('should handle empty app list', () => {
      const results = detectAppSecurityVulnerabilities([], false);
      expect(results.length).toBe(0);
    });

    it('should include affected entities when includeDetails=true', () => {
      const apps: AzureApp[] = [
        createApp({ id: 'app-1', displayName: 'Vulnerable App' } as any),
      ];

      (apps[0] as any).owners = [];

      const results = detectAppSecurityVulnerabilities(apps, true);

      const noOwnerFinding = results.find((r) => r.type === 'AZURE_APP_NO_OWNER');
      expect(noOwnerFinding?.affectedEntities).toBeDefined();
      expect(noOwnerFinding?.affectedEntities).toContain('Vulnerable App');
    });
  });
});
