# Changelog

All notable changes to this project will be documented in this file.

## [1.5.2] - 2026-02-02

### Features

- **SaaS Integration Mode**: Dual-mode support for standalone and SaaS operation
  - CLI commands: `--enroll`, `--daemon`, `--status`, `--unenroll`
  - Automatic enrollment with SaaS platform
  - Polling-based command execution from fleet management
  - Encrypted local credential storage (AES-256-GCM)
  - Exponential backoff retry (1s → 5min max)
  - Support for RUN_AUDIT, RUN_AUDIT_AZURE, HEALTH_CHECK commands
  - Real-time audit execution with result push to SaaS

### Changed

- Server entry point now supports both standalone and SaaS modes
- DI container accepts external configuration for SaaS mode
- Enhanced configuration adapter for dynamic config management

### Added

- CLI argument parser (`src/cli/index.ts`)
- SaaS types and interfaces (`src/types/saas.types.ts`)
- SaaS client service for fleet API communication
- Credential store with machine-specific encryption
- Daemon service with polling loop
- Command handler for SaaS commands
- Config adapter for SaaS-to-app config conversion

## [1.4.0] - 2026-02-02

Initial public release.

### Features

- Active Directory security auditing with 87 vulnerability detectors
- Azure AD security auditing with 27 vulnerability detectors
- REST API with JWT authentication
- Export to JSON and CSV formats
- Docker and npm distribution
