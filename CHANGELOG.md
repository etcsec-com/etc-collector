# Changelog

All notable changes to ETC Collector will be documented in this file.

## [1.5.9] - 2025-02-04

### Fixed
- **Windows service working directory**: Fixed credential store path resolution to use executable directory instead of current working directory. This allows the Windows service to find credentials regardless of the working directory it's started from.

### Note
- Windows service creation requires a service wrapper like NSSM (Non-Sucking Service Manager) since the collector runs as a console application.

## [1.5.8] - 2025-02-03

### Fixed
- **Windows VM compatibility**: Replaced Bun with `@yao-pkg/pkg` (Node.js) for Windows builds. Bun requires AVX2 CPU instructions not available on QEMU/Hyper-V/VMware virtual machines. pkg-based builds work on all x64 CPUs.

### Changed
- Windows binary now uses Node.js 20 runtime via pkg (58 MB vs 117 MB with Bun)
- Linux/macOS continue to use Bun for better performance

### Note
- Windows binary only supports SaaS mode (--enroll, --daemon, --status, --unenroll)
- Standalone mode (HTTP server) requires Linux/macOS

## [1.5.7] - 2025-02-03

### Fixed
- **Windows binary crash**: Created separate SaaS-only entry point (`server-saas.ts`) for Windows build that completely excludes all database and native module code. Windows build now uses this lightweight entry point.

### Note
- Windows binary only supports SaaS mode (--enroll, --daemon, --status, --unenroll)
- Standalone mode (HTTP server) requires Linux/macOS

## [1.5.6] - 2025-02-03

### Fixed
- **Windows binary crash**: Exclude `better-sqlite3` native module from Windows build with `--external` flag. The module is incompatible with Bun runtime on Windows.

## [1.5.5] - 2025-02-03

### Fixed
- Release rebuild (v1.5.4 workflow failed on npm publish)

## [1.5.4] - 2025-02-03

### Changed
- **Modular detector architecture**: Split 14 large detector files (300-700 lines each) into modular directory structure with individual files per detection function
- **Cleaner imports**: Removed redundant `.detector.ts` bridge files, imports now directly from directories
- **196 unique security checks** across 14 categories: accounts (32), advanced (48), computers (29), compliance (23), permissions (16), groups (15), kerberos (14), monitoring (13), network (12), adcs (11), attack-paths (11), password (10), gpo (9), trusts (7)

## [1.5.3] - 2025-02-02

### Fixed
- **Windows binary crash**: Fixed crash on Windows due to `better-sqlite3` native module incompatibility with Bun runtime. Database modules are now dynamically imported only when needed (standalone mode).

### Added
- **Verbose logging**: Added `--verbose` / `-V` flag for debug-level logging
- **Environment variable support**:
  - `ETCSEC_ENROLL_TOKEN` - Enrollment token (more secure than CLI argument)
  - `ETCSEC_VERBOSE` - Enable debug logging
- **Improved CLI help**: Better documentation of all options and environment variables

### Changed
- Default SaaS API URL changed to `https://api.etcsec.com`
- Database initialization is now skipped in SaaS mode for better Bun compatibility

## [1.5.2] - 2025-01-31

### Added
- **SaaS Integration Mode**: New collector mode for managed deployments
  - `--enroll` command for registration with SaaS platform
  - `--daemon` mode for automated audit execution
  - `--status` and `--unenroll` management commands
- Encrypted local credential storage (AES-256-GCM)
- Exponential backoff retry logic for network errors
- Health reporting to SaaS platform

## [1.5.1] - 2025-01-30

### Added
- Bun-based binary builds for all platforms (Linux, macOS, Windows)
- GitHub Actions release workflow

### Fixed
- Build and packaging improvements

## [1.4.0] - 2025-01-29

### Added
- Initial public release
- Active Directory security auditing
- Azure AD/Entra ID security auditing
- JWT-based API authentication
- SMB share scanning for SYSVOL
- LDAP signing detection
- 30+ security checks

## License

Apache-2.0
