/**
 * Configuration Service
 * Manages application configuration
 */

import { ConfigSchema } from '../../config/config.schema';
import { AppConfig } from '../../types/config.types';

/**
 * Load and validate application configuration
 *
 * @returns Promise<AppConfig> Validated configuration
 */
export async function loadConfig(): Promise<AppConfig> {
  // Load from environment variables
  const rawConfig = {
    server: {
      port: process.env['PORT'] || 8443,
      nodeEnv: process.env['NODE_ENV'] || 'production',
    },
    infoEndpoints: {
      tokenInfoEnabled: process.env['TOKEN_INFO_ENABLED'],
      providersInfoEnabled: process.env['PROVIDERS_INFO_ENABLED'],
    },
    jwt: {
      privateKeyPath: process.env['JWT_PRIVATE_KEY_PATH'] || './keys/private.pem',
      publicKeyPath: process.env['JWT_PUBLIC_KEY_PATH'] || './keys/public.pem',
      tokenExpiry: process.env['TOKEN_EXPIRY'] || '1h',
      tokenMaxUses: process.env['TOKEN_MAX_USES'] || 10,
    },
    ldap: {
      url: process.env['LDAP_URL'] || '',
      bindDN: process.env['LDAP_BIND_DN'] || '',
      bindPassword: process.env['LDAP_BIND_PASSWORD'] || '',
      baseDN: process.env['LDAP_BASE_DN'] || '',
      tlsVerify: process.env['LDAP_TLS_VERIFY'] !== 'false',
      caCertPath: process.env['LDAP_CA_CERT_PATH'],
      timeout: process.env['LDAP_TIMEOUT'] || 30000,
      skipHostnameVerification: process.env['LDAP_SKIP_HOSTNAME_VERIFICATION'],
      tlsServername: process.env['LDAP_TLS_SERVERNAME'],
    },
    azure: {
      enabled: process.env['AZURE_ENABLED'],
      tenantId: process.env['AZURE_TENANT_ID'],
      clientId: process.env['AZURE_CLIENT_ID'],
      clientSecret: process.env['AZURE_CLIENT_SECRET'],
    },
    smb: {
      enabled: process.env['SMB_ENABLED'],
      username: process.env['SMB_USERNAME'],
      password: process.env['SMB_PASSWORD'],
      timeout: process.env['SMB_TIMEOUT'] || 10000,
    },
    logging: {
      level: process.env['LOG_LEVEL'] || 'info',
      format: process.env['LOG_FORMAT'] || 'json',
    },
    database: {
      path: process.env['DATABASE_PATH'] || './data/etc-collector.db',
      enableWAL: process.env['DATABASE_ENABLE_WAL'] !== 'false',
      busyTimeout: process.env['DATABASE_BUSY_TIMEOUT'] || 5000,
    },
  };

  // Validate with Zod schema
  const config = ConfigSchema.parse(rawConfig);

  return config as AppConfig;
}

export class ConfigService {
  getConfig(): unknown {
    throw new Error('Config service not implemented yet');
  }
}
