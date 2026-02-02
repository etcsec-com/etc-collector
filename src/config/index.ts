import dotenv from 'dotenv';
import { ConfigSchema, Config } from './config.schema';

/**
 * Configuration Loader
 * Loads and validates environment variables with Zod
 */

// Load .env file in development
if (process.env['NODE_ENV'] === 'development') {
  dotenv.config();
}

/**
 * Load and validate configuration
 * Throws error if validation fails
 */
export function loadConfig(): Config {
  const rawConfig = {
    server: {
      port: process.env['PORT'],
      nodeEnv: process.env['NODE_ENV'],
    },
    infoEndpoints: {
      tokenInfoEnabled: process.env['TOKEN_INFO_ENABLED'],
      providersInfoEnabled: process.env['PROVIDERS_INFO_ENABLED'],
    },
    jwt: {
      privateKeyPath: process.env['JWT_PRIVATE_KEY_PATH'],
      publicKeyPath: process.env['JWT_PUBLIC_KEY_PATH'],
      tokenExpiry: process.env['TOKEN_EXPIRY'],
      tokenMaxUses: process.env['TOKEN_MAX_USES'],
    },
    ldap: {
      url: process.env['LDAP_URL'],
      bindDN: process.env['LDAP_BIND_DN'],
      bindPassword: process.env['LDAP_BIND_PASSWORD'],
      baseDN: process.env['LDAP_BASE_DN'],
      tlsVerify: process.env['LDAP_TLS_VERIFY'],
      caCertPath: process.env['LDAP_CA_CERT_PATH'],
      timeout: process.env['LDAP_TIMEOUT'],
      skipHostnameVerification: process.env['LDAP_SKIP_HOSTNAME_VERIFICATION'],
      tlsServername: process.env['LDAP_TLS_SERVERNAME'],
    },
    azure: {
      enabled: process.env['AZURE_ENABLED'],
      tenantId: process.env['AZURE_TENANT_ID'],
      tenantName: process.env['AZURE_TENANT_NAME'],
      clientId: process.env['AZURE_CLIENT_ID'],
      clientSecret: process.env['AZURE_CLIENT_SECRET'],
    },
    logging: {
      level: process.env['LOG_LEVEL'],
      format: process.env['LOG_FORMAT'],
    },
    database: {
      path: process.env['DB_PATH'] || process.env['DATABASE_PATH'],
      enableWAL: process.env['DB_ENABLE_WAL'],
      busyTimeout: process.env['DB_BUSY_TIMEOUT'],
    },
  };

  try {
    const config = ConfigSchema.parse(rawConfig);
    return config;
  } catch (error) {
    if (error instanceof Error) {
      throw new Error(`Configuration validation failed: ${error.message}`);
    }
    throw error;
  }
}

// Export singleton config instance
let configInstance: Config | null = null;

export function getConfig(): Config {
  if (!configInstance) {
    configInstance = loadConfig();
  }
  return configInstance;
}
