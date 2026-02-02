import { createApp } from './app';
import { getConfig } from './config';
import { logInfo, logError } from './utils/logger';
import { MigrationRunner } from './data/migrations/migration.runner';
import { DIContainer } from './container';
import { version } from '../package.json';

/**
 * Server Entry Point
 * Bootstraps the application and starts the HTTP server
 */

async function startServer(): Promise<void> {
  try {
    // Load configuration
    const config = getConfig();
    logInfo('Configuration loaded successfully', {
      port: config.server.port,
      nodeEnv: config.server.nodeEnv,
    });

    // Run database migrations
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

// Start the server
void startServer();
