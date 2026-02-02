import Database from 'better-sqlite3';
import { getConfig } from './config';
import { DatabaseManager } from './data/database';
import { TokenRepository } from './data/repositories/token.repository';
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

  // Database
  private db!: Database.Database;
  private dbManager!: DatabaseManager;

  // Repositories
  private tokenRepository!: TokenRepository;

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
   * @returns Promise<DIContainer> Initialized container instance
   */
  static async initialize(): Promise<DIContainer> {
    if (DIContainer.instance) {
      return DIContainer.instance;
    }

    const container = new DIContainer();
    await container.init();
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
  private async init(): Promise<void> {
    this.logger.info('Initializing DI container');

    // 1. Load configuration
    const config = getConfig();
    this.logger.debug('Configuration loaded', {
      port: config.server.port,
      env: config.server.nodeEnv,
      dbPath: config.database.path,
    });

    // 2. Initialize database and repositories
    this.dbManager = DatabaseManager.getInstance();
    this.db = this.dbManager.connect(config.database.path);
    this.tokenRepository = new TokenRepository(this.db);
    this.logger.debug('Database and repositories initialized');

    // 3. Initialize crypto service and load RSA keys
    this.cryptoService = new CryptoService(
      config.jwt.privateKeyPath,
      config.jwt.publicKeyPath
    );
    await this.cryptoService.loadOrGenerateKeys();
    this.logger.debug('Crypto service initialized and keys loaded');

    // 4. Initialize token service
    this.tokenService = new TokenService(this.tokenRepository, this.cryptoService);
    this.logger.debug('Token service initialized');

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

  getDatabase(): Database.Database {
    return this.db;
  }

  getTokenRepository(): TokenRepository {
    return this.tokenRepository;
  }

  getCryptoService(): CryptoService {
    return this.cryptoService;
  }

  getTokenService(): TokenService {
    return this.tokenService;
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
