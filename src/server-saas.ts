/**
 * SaaS-Only Server Entry Point (Windows Compatible)
 *
 * This entry point excludes all database-related code to avoid
 * native module issues on Windows with Bun runtime.
 */

import { version } from '../package.json';
import { parseArgs, validateArgs } from './cli';
import { logInfo, logError, setVerbose } from './utils/logger';
import { EnrollmentService } from './services/saas/enrollment.service';
import { SaaSClientService } from './services/saas/saas-client.service';
import { CommandHandlerService } from './services/saas/command-handler.service';
import { DaemonService } from './services/saas/daemon.service';
import { adaptSaaSConfig } from './services/saas/config-adapter';

const HELP_TEXT = `
ETC Collector - Active Directory Security Auditor v${version}
(SaaS Mode Only - Windows Build)

Usage:
  etc-collector --enroll [options]  Enroll with SaaS platform
  etc-collector --daemon            Run as SaaS agent (after enrollment)
  etc-collector --status            Show enrollment status
  etc-collector --unenroll          Remove enrollment

Enrollment options:
  --token=TOKEN       Enrollment token (or set ETCSEC_ENROLL_TOKEN env var)
  --saas-url=URL      SaaS API URL (default: https://api.etcsec.com)

Environment variables:
  ETCSEC_ENROLL_TOKEN   Enrollment token (more secure than --token)
  ETCSEC_VERBOSE        Set to 'true' to enable debug logging

Options:
  --help, -h          Show this help message
  --version, -v       Show version number
  --verbose, -V       Enable verbose/debug logging
`;

async function main(): Promise<void> {
  try {
    const args = parseArgs();

    // Enable verbose logging if requested
    if (args.verbose || process.env['ETCSEC_VERBOSE'] === 'true') {
      setVerbose(true);
      logInfo('Verbose logging enabled');
    }

    logInfo('ETC Collector starting', { version, mode: 'saas-only', platform: process.platform });

    // Handle help
    if (args.help) {
      console.log(HELP_TEXT);
      process.exit(0);
    }

    // Handle version
    if (args.version) {
      console.log(version);
      process.exit(0);
    }

    const enrollmentService = new EnrollmentService();

    // Validate arguments
    const validation = validateArgs(args);
    if (!validation.valid) {
      console.error(`\n❌ Error: ${validation.error}\n`);
      console.log(HELP_TEXT);
      process.exit(1);
    }

    // Handle enrollment
    if (args.enroll) {
      logInfo('Starting enrollment process');
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

      logInfo('Config adapted for LDAP', { url: appConfig.ldap.url });

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

    // No valid command - show help
    if (!args.enroll && !args.daemon && !args.status && !args.unenroll) {
      console.log(HELP_TEXT);
      console.error('\n❌ Error: This Windows build only supports SaaS mode.');
      console.error('   Use --enroll to register with ETC SaaS platform.\n');
      process.exit(1);
    }
  } catch (error) {
    logError('Fatal error', error as Error);
    console.error(`\n❌ Fatal error: ${(error as Error).message}\n`);
    process.exit(1);
  }
}

// Start
void main();
