# etc-collector-com

> Active Directory and Azure AD security auditing tool with comprehensive vulnerability detection

## Overview

etc-collector-com is a security auditing tool designed to scan Active Directory and Azure AD environments for vulnerabilities and misconfigurations. It detects 87 AD vulnerability types and 27 Azure vulnerability types, providing detailed risk assessments and remediation recommendations.

## Features

- **11 REST API Endpoints**: Comprehensive API for audit operations, authentication, and exports
- **114 Vulnerability Types**: 87 AD + 27 Azure security checks
- **JWT Authentication**: Secure RS256 token-based authentication
- **Multiple Export Formats**: JSON and CSV export capabilities
- **Rate Limited**: Built-in rate limiting for API protection
- **Dockerized**: Ready-to-deploy Docker container (<150MB)
- **TypeScript**: Fully typed with strict mode enabled
- **Well Tested**: ≥80% code coverage target

## Prerequisites

- **Node.js**: 20.x LTS or higher
- **Docker**: 24+ (for containerized deployment)
- **npm**: 10.x or higher

## Installation

### Local Development Setup

1. **Clone the repository**
   ```bash
   git clone https://github.com/etcsec-com/etc-collector.git
   cd etc-collector
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Configure environment**
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

4. **Run in development mode**
   ```bash
   npm run dev
   ```

### Docker Deployment

1. **Using Docker Compose (Recommended)**
   ```bash
   docker-compose up -d
   ```

2. **Using Docker directly**
   ```bash
   docker build -t etc-collector .
   docker run -d -p 8443:8443 \
     --env-file .env \
     -v ./data:/app/data \
     -v ./logs:/app/logs \
     etc-collector
   ```

## Configuration

Copy `.env.example` to `.env` and configure the following:

- **Server**: Port and Node environment
- **LDAP**: Active Directory connection details
- **JWT**: Authentication secret and token settings
- **Azure**: Azure AD credentials (optional)
- **Logging**: Log level and format
- **Database**: SQLite database path

See `.env.example` for detailed configuration options.

## Usage

### Running Tests

```bash
# Run all tests
npm test

# Run tests in watch mode
npm run test:watch

# Run tests with coverage
npm run test:coverage
```

### Building for Production

```bash
# Compile TypeScript
npm run build

# Run production build
npm run start
```

### Code Quality

```bash
# Lint code
npm run lint

# Fix linting issues
npm run lint:fix

# Format code with Prettier
npm run format

# Type check without compilation
npm run typecheck
```

## Project Structure

```
etc-collector-com/
├── src/                    # TypeScript source code
│   ├── api/               # API controllers, routes, middlewares
│   ├── services/          # Business logic
│   ├── providers/         # LDAP and Azure providers
│   ├── data/              # Database repositories and models
│   ├── types/             # TypeScript type definitions
│   ├── utils/             # Utility functions
│   └── server.ts          # Server entry point
├── tests/                 # Test suite
│   ├── unit/              # Unit tests
│   ├── integration/       # Integration tests
│   └── e2e/               # End-to-end tests
├── docs/                  # Documentation
├── scripts/               # Utility scripts
└── .github/workflows/     # CI/CD pipelines
```

## API Endpoints

The API provides 11 endpoints for audit operations:

1. `GET /health` - Health check
2. `POST /api/v1/auth/token` - Generate JWT token
3. `POST /api/v1/auth/validate` - Validate token
4. `POST /api/v1/auth/revoke` - Revoke token
5. `GET /api/v1/auth/tokens` - List tokens
6. `POST /api/v1/audit/ad` - Run AD audit
7. `GET /api/v1/audit/ad/status` - Test LDAP connection
8. `POST /api/v1/audit/ad/export` - Export AD audit
9. `POST /api/v1/audit/azure` - Run Azure audit
10. `GET /api/v1/audit/azure/status` - Test Graph connection
11. `POST /api/v1/audit/azure/export` - Export Azure audit

For detailed API documentation, see [docs/api/](docs/api/).

## Development

### Coding Standards

- **TypeScript Strict Mode**: All strict flags enabled
- **Max File Size**: 300 lines per file (enforced by ESLint)
- **Max Complexity**: 10 cyclomatic complexity
- **Max Nesting**: 3 levels deep
- **No `any` Types**: Explicit types required

See the source code for coding style examples.

### Contributing

1. Create a feature branch
2. Make your changes
3. Ensure tests pass: `npm test`
4. Ensure linting passes: `npm run lint`
5. Ensure type checking passes: `npm run typecheck`
6. Submit a pull request

## Documentation

- **[API Reference](docs/api/)**: OpenAPI specification and usage guide

## License

ISC

## Support

For issues and feature requests, please visit:
https://github.com/etcsec-com/etc-collector/issues
