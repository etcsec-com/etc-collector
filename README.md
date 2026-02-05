# ETC Collector

Active Directory security audit tool. Detects misconfigurations, vulnerabilities, and compliance issues.

## Features

- **226 Security Detectors**: Comprehensive AD security checks
- **Multi-Platform**: Windows, Linux, macOS, Docker
- **REST API**: Easy integration with existing tools
- **Single Binary**: No dependencies, easy deployment
- **JWT Authentication**: Secure API access

## Quick Start

### Download

Download the latest release for your platform from [Releases](https://github.com/etcsec-com/etc-collector/releases).

### Run Audit

```bash
# Windows
etc-collector.exe audit --ldap-url ldaps://dc.example.com:636 \
  --ldap-bind-dn "CN=service,CN=Users,DC=example,DC=com" \
  --ldap-bind-password "password" \
  --ldap-base-dn "DC=example,DC=com"

# Linux/macOS
./etc-collector audit --ldap-url ldaps://dc.example.com:636 \
  --ldap-bind-dn "CN=service,CN=Users,DC=example,DC=com" \
  --ldap-bind-password "password" \
  --ldap-base-dn "DC=example,DC=com"
```

### Run as Server

```bash
# Start API server
./etc-collector server --port 8443 \
  --ldap-url ldaps://dc.example.com:636 \
  --ldap-bind-dn "CN=service,CN=Users,DC=example,DC=com" \
  --ldap-bind-password "password" \
  --ldap-base-dn "DC=example,DC=com"

# Generate JWT token
curl -X POST http://localhost:8443/api/v1/auth/token

# Run audit via API
curl -X POST http://localhost:8443/api/v1/audit/ad \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"includeDetails": false}'
```

## Docker

```bash
docker run -d --name etc-collector \
  -p 8443:8443 \
  -e LDAP_URL=ldaps://dc.example.com:636 \
  -e LDAP_BIND_DN="CN=service,CN=Users,DC=example,DC=com" \
  -e LDAP_BIND_PASSWORD="password" \
  -e LDAP_BASE_DN="DC=example,DC=com" \
  ghcr.io/etcsec-com/etc-collector:latest
```

## Configuration

Environment variables:

| Variable | Description | Required |
|----------|-------------|----------|
| `LDAP_URL` | LDAP server URL (ldaps://...) | Yes |
| `LDAP_BIND_DN` | Service account DN | Yes |
| `LDAP_BIND_PASSWORD` | Service account password | Yes |
| `LDAP_BASE_DN` | Base DN for searches | Yes |
| `LDAP_TLS_VERIFY` | Verify TLS certificate (default: true) | No |
| `LOG_LEVEL` | Log level: debug, info, warn, error | No |
| `LOG_FORMAT` | Log format: json, text | No |

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/auth/token` | Generate JWT token |
| POST | `/api/v1/audit/ad` | Run AD audit |
| GET | `/api/v1/audit/ad/status` | Get audit status |
| GET | `/api/v1/info/providers` | List configured providers |
| GET | `/health` | Health check |

## Building from Source

```bash
# Clone
git clone https://github.com/etcsec-com/etc-collector.git
cd etc-collector

# Build
go build -o bin/etc-collector ./cmd/etc-collector

# Build all platforms
make build-all
```

## Security Detectors

Categories:
- **Accounts** (32): Privileged accounts, service accounts, stale accounts
- **Computers** (26): LAPS, delegation, obsolete OS
- **Kerberos** (13): AS-REP roasting, Kerberoasting, delegation
- **Permissions** (15): Dangerous ACLs, GenericAll, WriteDACL
- **Groups** (15): Oversized groups, privileged membership
- **GPO** (9): Weak policies, unlinked GPOs
- **ADCS** (11): ESC1-11 vulnerabilities
- **Compliance** (23): ANSSI, CIS, NIST, DISA
- **Network** (12): LDAP/SMB signing, DNSSEC
- **Attack Paths** (10): Kerberoasting to DA, nested admin paths

## License

MIT License - see [LICENSE](LICENSE)

## Contributing

Issues and PRs welcome at https://github.com/etcsec-com/etc-collector
