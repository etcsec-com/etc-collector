import { Request, Response, NextFunction } from 'express';
import type { Logger } from 'winston';
import { logger } from '../../utils/logger';
import { LDAPConfig, AzureConfig } from '../../types/config.types';
import { GraphProvider } from '../../providers/azure/graph.provider';

/**
 * Provider info without sensitive data
 */
interface ProviderInfo {
  name: string;
  enabled: boolean;
  status: 'configured' | 'not_configured' | 'partial';
  details?: Record<string, unknown>;
}

/**
 * ProvidersController
 *
 * Handles provider information endpoints.
 *
 * Endpoints:
 * - GET /api/v1/providers/info - Get all configured providers info
 */
export class ProvidersController {
  private logger: Logger;

  constructor(
    private ldapConfig: LDAPConfig,
    private azureConfig: AzureConfig,
    private graphProvider?: GraphProvider
  ) {
    this.logger = logger;
  }

  /**
   * GET /api/v1/providers/info
   * Get information about all configured providers
   *
   * This endpoint requires PROVIDERS_INFO_ENABLED=true.
   * Returns non-sensitive configuration details for each provider.
   *
   * Response:
   * - 200: Providers information
   * - 500: Server error
   */
  async getProvidersInfo(_req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const providers: ProviderInfo[] = [];

      // LDAP/Active Directory provider
      const ldapProvider = this.getLDAPProviderInfo();
      providers.push(ldapProvider);

      // Azure/Entra ID provider - use config tenantName or fetch from API
      let tenantInfo: { displayName: string; verifiedDomains: string[] } | null = null;
      if (this.azureConfig.tenantName) {
        // Use configured tenant name
        tenantInfo = { displayName: this.azureConfig.tenantName, verifiedDomains: [] };
      } else if (this.graphProvider && this.azureConfig.enabled) {
        // Try to fetch from API
        try {
          const org = await this.graphProvider.getOrganization();
          tenantInfo = { displayName: org.displayName, verifiedDomains: org.verifiedDomains };
        } catch (err) {
          this.logger.debug('Could not fetch Azure organization info', { error: err });
        }
      }
      const azureProvider = this.getAzureProviderInfo(tenantInfo);
      providers.push(azureProvider);

      this.logger.debug('Providers info requested', {
        providerCount: providers.length,
        providers: providers.map((p) => ({ name: p.name, enabled: p.enabled })),
      });

      res.json({
        success: true,
        providers,
        summary: {
          total: providers.length,
          enabled: providers.filter((p) => p.enabled).length,
          configured: providers.filter((p) => p.status === 'configured').length,
        },
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Get LDAP provider info (non-sensitive)
   */
  private getLDAPProviderInfo(): ProviderInfo {
    const hasUrl = !!this.ldapConfig.url;
    const hasBindDN = !!this.ldapConfig.bindDN;
    const hasBaseDN = !!this.ldapConfig.baseDN;
    const hasPassword = !!this.ldapConfig.bindPassword;

    const isConfigured = hasUrl && hasBindDN && hasBaseDN && hasPassword;
    const isPartial = (hasUrl || hasBindDN || hasBaseDN) && !isConfigured;

    // Extract domain from URL without exposing IP
    let serverInfo = 'not configured';
    if (hasUrl) {
      try {
        const url = new URL(this.ldapConfig.url);
        serverInfo = `${url.protocol}//${url.hostname}:${url.port || (url.protocol === 'ldaps:' ? '636' : '389')}`;
      } catch {
        serverInfo = 'invalid URL';
      }
    }

    return {
      name: 'active-directory',
      enabled: isConfigured,
      status: isConfigured ? 'configured' : isPartial ? 'partial' : 'not_configured',
      details: {
        server: serverInfo,
        baseDN: this.ldapConfig.baseDN || 'not configured',
        tlsVerify: this.ldapConfig.tlsVerify,
        timeout: this.ldapConfig.timeout,
        hasCACert: !!this.ldapConfig.caCertPath,
      },
    };
  }

  /**
   * Get Azure provider info (non-sensitive)
   */
  private getAzureProviderInfo(
    tenantInfo: { displayName: string; verifiedDomains: string[] } | null
  ): ProviderInfo {
    const isEnabled = this.azureConfig.enabled;
    const hasTenantId = !!this.azureConfig.tenantId;
    const hasClientId = !!this.azureConfig.clientId;
    const hasClientSecret = !!this.azureConfig.clientSecret;

    const isConfigured = isEnabled && hasTenantId && hasClientId && hasClientSecret;
    const isPartial = isEnabled && !isConfigured;

    return {
      name: 'azure-entra-id',
      enabled: isEnabled,
      status: isConfigured ? 'configured' : isPartial ? 'partial' : 'not_configured',
      details: {
        tenantName: tenantInfo?.displayName || 'not available',
        tenantId: this.azureConfig.tenantId || 'not configured',
        verifiedDomains: tenantInfo?.verifiedDomains || [],
        clientId: hasClientId ? this.maskString(this.azureConfig.clientId!) : 'not configured',
        hasClientSecret: hasClientSecret,
      },
    };
  }

  /**
   * Mask a string for display (show first and last 4 chars)
   */
  private maskString(str: string): string {
    if (str.length <= 8) {
      return '****';
    }
    return `${str.substring(0, 4)}...${str.substring(str.length - 4)}`;
  }
}
