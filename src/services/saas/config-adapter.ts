/**
 * Config Adapter
 * Converts SaaS CollectorConfig to application Config
 */

import { CollectorConfig } from '../../types/saas.types';
import { Config } from '../../config/config.schema';

/**
 * Convert SaaS CollectorConfig to full application Config
 * Uses defaults for fields not provided by SaaS
 */
export function adaptSaaSConfig(saasConfig: CollectorConfig): Config {
  const config: Config = {
    server: {
      port: 8443,
      nodeEnv: 'production' as const,
    },
    infoEndpoints: {
      tokenInfoEnabled: false,
      providersInfoEnabled: false,
    },
    jwt: {
      privateKeyPath: './keys/private.pem',
      publicKeyPath: './keys/public.pem',
      tokenExpiry: '1h',
      tokenMaxUses: 10,
    },
    ldap: {
      url: saasConfig.ldap?.url || '',
      bindDN: saasConfig.ldap?.bindDN || '',
      bindPassword: saasConfig.ldap?.bindPassword || '',
      baseDN: saasConfig.ldap?.baseDN || '',
      tlsVerify: saasConfig.ldap?.tlsVerify ?? true,
      caCertPath: saasConfig.ldap?.caCert,
      timeout: saasConfig.ldap?.timeout || 30000,
      skipHostnameVerification: saasConfig.ldap?.skipHostnameVerification ?? false,
      tlsServername: saasConfig.ldap?.tlsServername,
    },
    azure: {
      enabled: saasConfig.azure?.enabled ?? false,
      tenantId: saasConfig.azure?.tenantId,
      tenantName: saasConfig.azure?.tenantName,
      clientId: saasConfig.azure?.clientId,
      clientSecret: saasConfig.azure?.clientSecret,
    },
    smb: {
      enabled: false,
      timeout: 10000,
    },
    logging: {
      level: 'info' as const,
      format: 'json' as const,
    },
    database: {
      path: './data/etc-collector.db',
      enableWAL: true,
      busyTimeout: 5000,
    },
  };

  return config;
}
