# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.1.0] - 2025-02-05

### Added
- GPO Links collection for GPO-based detectors
- GPO ACLs collection for permission analysis
- ACL collection for all permission-based detectors

### Fixed
- JSON response structure now matches TypeScript implementation
- Detector IDs aligned with TypeScript for SaaS compatibility
- Duplicate detector registration causing panic on startup
- Regex compatibility (removed unsupported Perl lookaheads)
- LDAP connection management (keep-alive for server mode)

### Changed
- Improved detector loading via init() registration
- Better error handling in LDAP provider

## [2.0.0] - 2025-02-05

### Changed
- **Complete rewrite in Go** - Single binary, no runtime dependencies
- Improved performance and reduced memory usage
- Native Windows support without Node.js

### Added
- 226 security detectors for Active Directory
- REST API with JWT authentication
- Docker support (linux/amd64, linux/arm64)
- Multi-platform binaries (Windows, Linux, macOS)
- Health check endpoint
- Structured JSON logging

### Security Detectors
- Accounts (32): Privileged accounts, service accounts, stale accounts
- Computers (26): LAPS, delegation, obsolete OS
- Kerberos (13): AS-REP roasting, Kerberoasting, delegation
- Permissions (15): Dangerous ACLs, GenericAll, WriteDACL
- Groups (15): Oversized groups, privileged membership
- GPO (9): Weak policies, unlinked GPOs
- ADCS (11): ESC1-11 certificate vulnerabilities
- Compliance (23): ANSSI, CIS, NIST, DISA frameworks
- Network (12): LDAP/SMB signing, DNSSEC
- Attack Paths (10): Privilege escalation paths

### API Endpoints
- `POST /api/v1/auth/token` - Generate JWT token
- `POST /api/v1/audit/ad` - Run AD audit
- `GET /api/v1/audit/ad/status` - Audit status
- `GET /api/v1/info/providers` - Provider info
- `GET /health` - Health check
