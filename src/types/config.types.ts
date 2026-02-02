/**
 * Configuration Types
 */

export interface ServerConfig {
  port: number;
  nodeEnv: 'development' | 'production' | 'test';
}

export interface JWTConfig {
  privateKeyPath: string;
  publicKeyPath: string;
  tokenExpiry: string;
  tokenMaxUses: number;
}

export interface InfoEndpointsConfig {
  tokenInfoEnabled: boolean;
  providersInfoEnabled: boolean;
}

export interface LDAPConfig {
  url: string;
  bindDN: string;
  bindPassword: string;
  baseDN: string;
  tlsVerify: boolean;
  caCertPath?: string;
  timeout: number;
  skipHostnameVerification?: boolean;
  tlsServername?: string;
}

export interface AzureConfig {
  enabled: boolean;
  tenantId?: string;
  tenantName?: string;
  clientId?: string;
  clientSecret?: string;
}

export interface SMBConfig {
  enabled: boolean;
  /** Username for SMB auth (defaults to LDAP user if not set) */
  username?: string;
  /** Password for SMB auth (defaults to LDAP password if not set) */
  password?: string;
  /** Connection timeout in ms */
  timeout: number;
}

/** Azure config with required credentials (for GraphProvider) */
export interface AzureProviderConfig {
  tenantId: string;
  clientId: string;
  clientSecret: string;
}

export interface LoggingConfig {
  level: 'error' | 'warn' | 'info' | 'debug';
  format: 'json' | 'simple';
}

export interface DatabaseConfig {
  path: string;
  enableWAL: boolean;
  busyTimeout: number;
}

export interface AppConfig {
  server: ServerConfig;
  infoEndpoints: InfoEndpointsConfig;
  jwt: JWTConfig;
  ldap: LDAPConfig;
  azure: AzureConfig;
  smb: SMBConfig;
  logging: LoggingConfig;
  database: DatabaseConfig;
}
