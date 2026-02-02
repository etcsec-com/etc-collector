// Note: better-sqlite3 is dynamically imported to avoid crashes on Windows with Bun
// Database-related imports are done dynamically in init() method
import { getConfig } from './config';
import { CryptoService } from './services/auth/crypto.service';
import { TokenService } from './services/auth/token.service';
import { HealthController } from './api/controllers/health.controller';
import { AuthController } from './api/controllers/auth.controller';
import { AuditController } from './api/controllers/audit.controller';
import { ExportController } from './api/controllers/export.controller';
import { ProvidersController } from './api/controllers/providers.controller';
import { LDAPProvider } from './providers/ldap/ldap.provider';
import { GraphProvider } from './providers/azure/graph.provider';
import type { Logger } from 'winston';
import { logger } from './utils/logger';
import { InfoEndpointsConfig } from './types/config.types';

// Lazy-loaded database types
type DatabaseType = import('better-sqlite3').Database;
type TokenRepositoryType = import('./data/repositories/token.repository').TokenRepository;
type DatabaseManagerType = import('./data/database').DatabaseManager;

/**
 * Dependency Injection Container
 *
 * Manages all application dependencies with singleton pattern.
 * Handles proper initialization order:
 * 1. Config
 * 2. Database + Repositories
 * 3. CryptoService (loads RSA keys)
 * 4. TokenService
 * 5. LDAP Provider
 * 6. Azure Graph Provider
 * 7. Controllers
 *
 * Updated: Story 1.4 (JWT), Story 1.5 (LDAP), Story 1.6 (Azure)
 */
export class DIContainer {
  private static instance: DIContainer | null = null;
  private logger: Logger;

  // Database (optional - not used in SaaS mode)
  private db: DatabaseType | null = null;
  private dbManager: DatabaseManagerType | null = null;

  // Repositories (optional - not used in SaaS mode)
  private tokenRepository: TokenRepositoryType | null = null;

  // Flag to track if database is available
  private databaseEnabled: boolean = false;

  // Services
  private cryptoService!: CryptoService;
  private tokenService!: TokenService;

  // Providers
  private ldapProvider!: LDAPProvider;
  private graphProvider!: GraphProvider;

  // Controllers
  private healthController!: HealthController;
  private authController!: AuthController;
  private auditController!: AuditController;
  private exportController!: ExportController;
  private providersController!: ProvidersController;

  // Config
  private infoEndpointsConfig!: InfoEndpointsConfig;

  private constructor() {
    this.logger = logger;
  }

  /**
   * Get singleton instance
   *
   * @throws Error if instance not initialized (call initialize() first)
   */
  static getInstance(): DIContainer {
    if (!DIContainer.instance) {
      throw new Error('DIContainer not initialized. Call DIContainer.initialize() first.');
    }
    return DIContainer.instance;
  }

  /**
   * Initialize DI container with async dependencies
   *
   * This method must be called before using the container.
   * It loads configuration, initializes database, loads RSA keys, and creates all services.
   *
   * @param externalConfig - Optional config (for SaaS mode). If not provided, loads from environment
   * @param options - Optional initialization options
   * @param options.skipDatabase - Skip database initialization (for SaaS mode on Bun)
   * @returns Promise<DIContainer> Initialized container instance
   */
  static async initialize(
    externalConfig?: any,
    options?: { skipDatabase?: boolean }
  ): Promise<DIContainer> {
    if (DIContainer.instance) {
      return DIContainer.instance;
    }

    const container = new DIContainer();
    await container.init(externalConfig, options);
    DIContainer.instance = container;
    return container;
  }

  /**
   * Reset singleton instance (for testing)
   */
  static reset(): void {
    DIContainer.instance = null;
  }

  /**
   * Internal initialization logic
   */
  private async init(externalConfig?: any, options?: { skipDatabase?: boolean }): Promise<void> {
    this.logger.info('Initializing DI container');

    // 1. Load configuration
    const config = externalConfig || getConfig();
    this.logger.debug('Configuration loaded', {
      port: config.server?.port,
      env: config.server?.nodeEnv,
      dbPath: config.database?.path,
      skipDatabase: options?.skipDatabase,
    });

    // 2. Initialize database and repositories (skip for SaaS mode)
    if (!options?.skipDatabase && config.database?.path) {
      try {
        // Dynamic import to avoid loading better-sqlite3 in SaaS/Bun mode
        const { DatabaseManager } = await import('./data/database');
        const { TokenRepository } = await import('./data/repositories/token.repository');

        this.dbManager = DatabaseManager.getInstance();
        this.db = this.dbManager.connect(config.database.path);
        this.tokenRepository = new TokenRepository(this.db);
        this.databaseEnabled = true;
        this.logger.debug('Database and repositories initialized');
      } catch (error) {
        this.logger.warn('Database initialization skipped or failed', {
          error: (error as Error).message,
        });
        // Continue without database - SaaS mode doesn't need it
      }
    } else {
      this.logger.info('Database initialization skipped (SaaS mode)');
    }

    // 3. Initialize crypto service and load RSA keys (only if database is enabled)
    if (this.databaseEnabled && config.jwt?.privateKeyPath && config.jwt?.publicKeyPath) {
      this.cryptoService = new CryptoService(
        config.jwt.privateKeyPath,
        config.jwt.publicKeyPath
      );
      await this.cryptoService.loadOrGenerateKeys();
      this.logger.debug('Crypto service initialized and keys loaded');

      // 4. Initialize token service (only if database is enabled)
      if (this.tokenRepository) {
        this.tokenService = new TokenService(this.tokenRepository, this.cryptoService);
        this.logger.debug('Token service initialized');
      }
    } else if (!options?.skipDatabase) {
      this.logger.info('Crypto/Token services skipped (no JWT config)');
    }

    // 5. Initialize LDAP provider
    this.ldapProvider = new LDAPProvider(config.ldap);
    this.logger.debug('LDAP provider initialized', {
      url: config.ldap.url,
      baseDN: config.ldap.baseDN,
    });

    // 6. Initialize Azure Graph provider (only if enabled)
    if (config.azure.enabled && config.azure.tenantId && config.azure.clientId && config.azure.clientSecret) {
      this.graphProvider = new GraphProvider({
        tenantId: config.azure.tenantId,
        clientId: config.azure.clientId,
        clientSecret: config.azure.clientSecret,
      });
      this.logger.debug('Azure Graph provider initialized', {
        tenantId: config.azure.tenantId,
        clientId: config.azure.clientId,
      });
    } else {
      this.logger.info('Azure provider disabled (AZURE_ENABLED=false or missing credentials)');
    }

    // 7. Initialize controllers
    this.healthController = new HealthController();
    this.authController = new AuthController(this.tokenService, config.jwt);
    this.auditController = new AuditController();
    this.exportController = new ExportController();
    this.providersController = new ProvidersController(config.ldap, config.azure, this.graphProvider);
    this.logger.debug('Controllers initialized');

    // 8. Store config for routes
    this.infoEndpointsConfig = config.infoEndpoints;

    this.logger.info('DI container initialization complete');
  }

  // === Getters ===

  getDatabase(): DatabaseType {
    if (!this.db) {
      throw new Error('Database not initialized. Are you running in SaaS mode?');
    }
    return this.db;
  }

  getTokenRepository(): TokenRepositoryType {
    if (!this.tokenRepository) {
      throw new Error('TokenRepository not initialized. Are you running in SaaS mode?');
    }
    return this.tokenRepository;
  }

  getCryptoService(): CryptoService {
    if (!this.cryptoService) {
      throw new Error('CryptoService not initialized. Are you running in SaaS mode?');
    }
    return this.cryptoService;
  }

  getTokenService(): TokenService {
    if (!this.tokenService) {
      throw new Error('TokenService not initialized. Are you running in SaaS mode?');
    }
    return this.tokenService;
  }

  isDatabaseEnabled(): boolean {
    return this.databaseEnabled;
  }

  getLDAPProvider(): LDAPProvider {
    return this.ldapProvider;
  }

  getGraphProvider(): GraphProvider {
    return this.graphProvider;
  }

  getHealthController(): HealthController {
    return this.healthController;
  }

  getAuthController(): AuthController {
    return this.authController;
  }

  getAuditController(): AuditController {
    return this.auditController;
  }

  getExportController(): ExportController {
    return this.exportController;
  }

  getProvidersController(): ProvidersController {
    return this.providersController;
  }

  getInfoEndpointsConfig(): InfoEndpointsConfig {
    return this.infoEndpointsConfig;
  }
}
