import { z } from 'zod';

/**
 * Configuration Schema (Zod validation)
 * Validates all environment variables at startup
 */

const ConfigSchema = z.object({
  server: z.object({
    port: z.coerce.number().int().positive().default(8443),
    nodeEnv: z.enum(['development', 'production', 'test']).default('production'),
  }),

  // Info endpoints configuration (disabled by default for security)
  infoEndpoints: z.object({
    tokenInfoEnabled: z
      .union([z.boolean(), z.string()])
      .transform((val) => {
        if (typeof val === 'boolean') return val;
        return val === 'true' || val === '1';
      })
      .default(false),
    providersInfoEnabled: z
      .union([z.boolean(), z.string()])
      .transform((val) => {
        if (typeof val === 'boolean') return val;
        return val === 'true' || val === '1';
      })
      .default(false),
  }),

  jwt: z.object({
    privateKeyPath: z.string().default('./keys/private.pem'),
    publicKeyPath: z.string().default('./keys/public.pem'),
    tokenExpiry: z.string().default('1h'),
    tokenMaxUses: z.coerce.number().int().min(0).default(10),
  }),

  ldap: z.object({
    url: z.string().url('LDAP_URL must be a valid URL'),
    bindDN: z.string().min(1, 'LDAP_BIND_DN is required'),
    bindPassword: z.string().min(1, 'LDAP_BIND_PASSWORD is required'),
    baseDN: z.string().min(1, 'LDAP_BASE_DN is required'),
    tlsVerify: z.coerce.boolean().default(true),
    caCertPath: z.string().optional(),
    timeout: z.coerce.number().int().positive().default(30000),
    skipHostnameVerification: z.coerce.boolean().default(false),
    tlsServername: z.string().optional(),
  }),

  azure: z
    .object({
      enabled: z
        .union([z.boolean(), z.string()])
        .transform((val) => {
          if (typeof val === 'boolean') return val;
          return val === 'true' || val === '1';
        })
        .default(false),
      tenantId: z.string().optional(),
      tenantName: z.string().optional(),
      clientId: z.string().optional(),
      clientSecret: z.string().optional(),
    })
    .refine(
      (data) => {
        // If enabled, all fields are required
        if (data.enabled) {
          return data.tenantId && data.clientId && data.clientSecret;
        }
        return true;
      },
      {
        message: 'AZURE_TENANT_ID, AZURE_CLIENT_ID, and AZURE_CLIENT_SECRET are required when AZURE_ENABLED=true',
      }
    ),

  smb: z.object({
    enabled: z
      .union([z.boolean(), z.string()])
      .transform((val) => {
        if (typeof val === 'boolean') return val;
        return val === 'true' || val === '1';
      })
      .default(false),
    username: z.string().optional(),
    password: z.string().optional(),
    timeout: z.coerce.number().int().positive().default(10000),
  }).default({
    enabled: false,
    timeout: 10000,
  }),

  logging: z.object({
    level: z.enum(['error', 'warn', 'info', 'debug']).default('info'),
    format: z.enum(['json', 'simple']).default('json'),
  }),

  database: z.object({
    path: z.string().default('./data/etc-collector.db'),
    enableWAL: z.coerce.boolean().default(true),
    busyTimeout: z.coerce.number().int().positive().default(5000),
  }),
});

export type Config = z.infer<typeof ConfigSchema>;

export { ConfigSchema };
