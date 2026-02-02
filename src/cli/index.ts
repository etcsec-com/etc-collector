/**
 * CLI Argument Parser
 * Parses command-line arguments for SaaS and standalone modes
 */

import { CLIArgs } from '../types/saas.types';
import { version } from '../../package.json';

const HELP_TEXT = `
ETC Collector - Active Directory Security Auditor v${version}

Usage:
  etc-collector                     Start in standalone mode (HTTP server)
  etc-collector --enroll [options]  Enroll with SaaS platform
  etc-collector --daemon            Run as SaaS agent (after enrollment)
  etc-collector --status            Show enrollment status
  etc-collector --unenroll          Remove enrollment

Enrollment options:
  --token=TOKEN       Enrollment token (or set ETCSEC_ENROLL_TOKEN env var for security)
  --saas-url=URL      SaaS API URL (default: https://api.etcsec.com)

Environment variables:
  ETCSEC_ENROLL_TOKEN   Enrollment token (more secure than --token, not shown in ps)
  ETCSEC_VERBOSE        Set to 'true' to enable debug logging

Daemon options:
  --verbose, -V       Enable verbose logging (debug level)

Examples:
  # Standalone mode (open source)
  $ etc-collector

  # SaaS enrollment (token via argument)
  $ etc-collector --enroll --token=etcsec_enroll_abc123

  # SaaS enrollment (token via env var - more secure)
  $ ETCSEC_ENROLL_TOKEN=etcsec_enroll_abc123 etc-collector --enroll

  # Start as SaaS agent with verbose logging
  $ etc-collector --daemon --verbose

  # Check enrollment status
  $ etc-collector --status

Options:
  --help, -h          Show this help message
  --version, -v       Show version number
  --verbose, -V       Enable verbose/debug logging
`;

/**
 * Parse command-line arguments
 */
export function parseArgs(argv: string[] = process.argv.slice(2)): CLIArgs {
  const args: CLIArgs = {
    mode: 'standalone',
  };

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];

    switch (arg) {
      case '--help':
      case '-h':
        args.help = true;
        break;

      case '--version':
      case '-v':
        args.version = true;
        break;

      case '--verbose':
      case '-V':
        args.verbose = true;
        break;

      case '--enroll':
        args.enroll = true;
        args.mode = 'saas';
        break;

      case '--daemon':
        args.daemon = true;
        args.mode = 'saas';
        break;

      case '--status':
        args.status = true;
        args.mode = 'saas';
        break;

      case '--unenroll':
        args.unenroll = true;
        args.mode = 'saas';
        break;

      default:
        // Parse key=value arguments
        if (arg?.startsWith('--token=')) {
          args.token = arg.substring('--token='.length);
        } else if (arg?.startsWith('--saas-url=')) {
          args.saasUrl = arg.substring('--saas-url='.length);
        } else if (arg) {
          console.error(`Unknown argument: ${arg}`);
          console.error('Run with --help for usage information');
          process.exit(1);
        }
    }
  }

  // Read token from environment variable if not provided via argument
  // This is more secure as it doesn't appear in process list or shell history
  if (!args.token && process.env['ETCSEC_ENROLL_TOKEN']) {
    args.token = process.env['ETCSEC_ENROLL_TOKEN'];
  }

  // Read verbose from environment variable
  if (!args.verbose && process.env['ETCSEC_VERBOSE'] === 'true') {
    args.verbose = true;
  }

  return args;
}

/**
 * Display help text
 */
export function showHelp(): void {
  console.log(HELP_TEXT);
}

/**
 * Display version
 */
export function showVersion(): void {
  console.log(`ETC Collector v${version}`);
}

/**
 * Validate CLI arguments
 */
export function validateArgs(args: CLIArgs): { valid: boolean; error?: string } {
  // Help and version are always valid
  if (args.help || args.version) {
    return { valid: true };
  }

  // Enrollment requires token
  if (args.enroll && !args.token) {
    return {
      valid: false,
      error: 'Enrollment requires --token=<enrollment-token>',
    };
  }

  // Token format validation (basic)
  if (args.token && !args.token.startsWith('etcsec_enroll_')) {
    return {
      valid: false,
      error: 'Invalid enrollment token format. Expected: etcsec_enroll_xxx',
    };
  }

  // Daemon mode requires enrollment first
  if (args.daemon) {
    // This will be checked at runtime by loading credentials
    return { valid: true };
  }

  return { valid: true };
}
