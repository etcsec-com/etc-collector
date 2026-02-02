import { createApp } from './app';
import { getConfig } from './config';
import { logInfo, logError, setVerbose } from './utils/logger';
// Note: MigrationRunner is dynamically imported to avoid loading better-sqlite3 in SaaS mode
import { DIContainer } from './container';
import { version } from '../package.json';
import { parseArgs, validateArgs, showHelp, showVersion } from './cli';
import { EnrollmentService } from './services/saas/enrollment.service';
import { SaaSClientService } from './services/saas/saas-client.service';
import { CommandHandlerService } from './services/saas/command-handler.service';
import { DaemonService } from './services/saas/daemon.service';
import { adaptSaaSConfig } from './services/saas/config-adapter';

/**
 * Server Entry Point
 * Bootstraps the application in standalone or SaaS mode
 */

async function startStandaloneMode(): Promise<void> {
  try {
    // Load configuration
    const config = getConfig();
    logInfo('Configuration loaded successfully', {
      port: config.server.port,
      nodeEnv: config.server.nodeEnv,
    });

    // Run database migrations (dynamic import to avoid loading better-sqlite3 in SaaS mode)
    const { MigrationRunner } = await import('./data/migrations/migration.runner');
    await MigrationRunner.runMigrations(config.database.path);
    logInfo('Database migrations completed');

    // Initialize dependency injection container
    await DIContainer.initialize();
    logInfo('DI container initialized');

    // Create Express app
    const app = createApp();

    // Start HTTP server
    const server = app.listen(config.server.port, () => {
      logInfo('Server started successfully', {
        port: config.server.port,
        nodeEnv: config.server.nodeEnv,
        version,
        mode: 'standalone',
      });
    });

    // Graceful shutdown
    const shutdown = (): void => {
      logInfo('Shutdown signal received, closing server...');
      server.close(() => {
        logInfo('Server closed successfully');
        process.exit(0);
      });
    };

    process.on('SIGTERM', shutdown);
    process.on('SIGINT', shutdown);
  } catch (error) {
    logError('Failed to start server', error as Error);
    process.exit(1);
  }
}

async function startSaaSMode(): Promise<void> {
  try {
    const enrollmentService = new EnrollmentService();

    // Parse CLI arguments
    const args = parseArgs();

    // Enable verbose logging if requested
    if (args.verbose) {
      setVerbose(true);
    }

    // Validate arguments
    const validation = validateArgs(args);
    if (!validation.valid) {
      console.error(`\n❌ Error: ${validation.error}\n`);
      showHelp();
      process.exit(1);
    }

    // Handle help
    if (args.help) {
      showHelp();
      process.exit(0);
    }

    // Handle version
    if (args.version) {
      showVersion();
      process.exit(0);
    }

    // Handle enrollment
    if (args.enroll) {
      const saasUrl = args.saasUrl || 'https://api.etcsec.com';
      await enrollmentService.enroll(args.token!, saasUrl);
      process.exit(0);
    }

    // Handle status
    if (args.status) {
      await enrollmentService.showStatus();
      process.exit(0);
    }

    // Handle unenrollment
    if (args.unenroll) {
      await enrollmentService.unenroll();
      process.exit(0);
    }

    // Handle daemon mode
    if (args.daemon) {
      // Load credentials
      const credentials = await enrollmentService.loadCredentials();

      if (!credentials) {
        console.error('\n❌ Error: Collector is not enrolled');
        console.error('\nRun with --enroll first:\n');
        console.error('   etc-collector --enroll --token=<your-token>\n');
        process.exit(1);
      }

      console.log(`\n🚀 Starting ETC Collector in SaaS mode...`);
      console.log(`   Collector ID: ${credentials.collectorId}`);
      console.log(`   SaaS URL: ${credentials.saasUrl}`);
      console.log(`   Polling interval: ${credentials.config.polling.intervalSeconds}s\n`);

      // Convert SaaS config to application config
      const appConfig = adaptSaaSConfig(credentials.config);

      // Initialize DI container with adapted config (skip database for Bun compatibility)
      await DIContainer.initialize(appConfig, { skipDatabase: true });
      logInfo('DI container initialized with SaaS config');

      // Create SaaS client
      const saasClient = new SaaSClientService(credentials.saasUrl);
      saasClient.setCredentials(credentials.collectorId, credentials.apiKey);

      // Create command handler
      const commandHandler = new CommandHandlerService(credentials.config);

      // Create and start daemon
      const daemon = new DaemonService(saasClient, commandHandler, credentials.config);

      // Graceful shutdown
      const shutdown = (): void => {
        logInfo('Shutdown signal received, stopping daemon...');
        daemon.stop();
        process.exit(0);
      };

      process.on('SIGTERM', shutdown);
      process.on('SIGINT', shutdown);

      // Start daemon
      await daemon.start();

      console.log('✅ Daemon started successfully');
      console.log('   Press Ctrl+C to stop\n');
    }
  } catch (error) {
    logError('Failed to start SaaS mode', error as Error);
    console.error(`\n❌ Error: ${(error as Error).message}\n`);
    process.exit(1);
  }
}

async function main(): Promise<void> {
  const args = parseArgs();

  // Determine mode based on arguments
  if (args.mode === 'saas') {
    await startSaaSMode();
  } else {
    // Default to standalone mode
    await startStandaloneMode();
  }
}

// Start the application
void main();
