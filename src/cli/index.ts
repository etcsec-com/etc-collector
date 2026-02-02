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
  --token=TOKEN       Enrollment token from SaaS UI (required)
  --saas-url=URL      SaaS API URL (default: https://app.etcsec.com)

Examples:
  # Standalone mode (open source)
  $ etc-collector

  # SaaS enrollment
  $ etc-collector --enroll --token=etcsec_enroll_abc123

  # Start as SaaS agent
  $ etc-collector --daemon

  # Check enrollment status
  $ etc-collector --status

Options:
  --help, -h          Show this help message
  --version, -v       Show version number
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
