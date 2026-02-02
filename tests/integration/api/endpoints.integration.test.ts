/**
 * API Endpoints Integration Tests
 * Story 1.10: API Controllers & Routes
 *
 * Tests all 11 endpoints and verifies 5 IVs:
 * - IV1: All endpoints respond with correct status codes
 * - IV2: Authentication required on protected endpoints
 * - IV3: Rate limiting prevents abuse
 * - IV4: Validation rejects invalid requests
 * - IV5: Error responses follow consistent format
 */

import request, { Response } from 'supertest';
import express, { Express } from 'express';
import Database from 'better-sqlite3';
import { join } from 'path';
import { unlinkSync, existsSync } from 'fs';
import { createRoutes } from '../../../src/api/routes';
import { HealthController } from '../../../src/api/controllers/health.controller';
import { AuthController } from '../../../src/api/controllers/auth.controller';
import { AuditController } from '../../../src/api/controllers/audit.controller';
import { ExportController } from '../../../src/api/controllers/export.controller';
import { errorHandler } from '../../../src/api/middlewares/errorHandler';
import { SecurityScore } from '../../../src/services/audit/scoring.service';
import { ExportAuditResult } from '../../../src/services/export/export.service';
import { TokenService } from '../../../src/services/auth/token.service';
import { TokenRepository } from '../../../src/data/repositories/token.repository';
import { CryptoService } from '../../../src/services/auth/crypto.service';
import { DatabaseManager } from '../../../src/data/database';
import { MigrationRunner } from '../../../src/data/migrations/migration.runner';
import { ProvidersController } from '../../../src/api/controllers/providers.controller';
import { JWTConfig, InfoEndpointsConfig, LDAPConfig, AzureConfig } from '../../../src/types/config.types';

describe('API Endpoints Integration Tests', () => {
  let app: Express;
  let validToken: string;
  let db: Database.Database;

  const testDbPath = join(__dirname, '../../__test_data__/api-integration-test.db');
  const testPrivateKeyPath = join(__dirname, '../../__test_data__/keys/api-test-private.pem');
  const testPublicKeyPath = join(__dirname, '../../__test_data__/keys/api-test-public.pem');

  const mockScore: SecurityScore = {
    score: 75.5,
    rating: 'good',
    weightedPoints: 100,
    totalUsers: 1000,
    findings: {
      critical: 5,
      high: 10,
      medium: 20,
      low: 5,
      total: 40,
    },
    categories: {
      passwords: 25,
      kerberos: 5,
      accounts: 10,
      groups: 0,
      computers: 0,
      advanced: 0,
      permissions: 0,
      config: 0,
      adcs: 0,
      gpo: 0,
      trusts: 0,
      'attack-paths': 0,
      monitoring: 0,
      compliance: 0,
      network: 0,
      identity: 0,
      applications: 0,
      conditionalAccess: 0,
      privilegedAccess: 0,
    },
  };

  const mockExportAuditResult: ExportAuditResult = {
    score: mockScore,
    findings: [],
    stats: {
      totalUsers: 1000,
      totalGroups: 50,
      totalComputers: 100,
      totalFindings: 40,
      executionTimeMs: 5000,
    },
    timestamp: new Date('2026-01-12T10:30:00Z'),
  };

  beforeAll(async () => {
    // Clean up any existing test database
    if (existsSync(testDbPath)) {
      unlinkSync(testDbPath);
    }

    // Run migrations
    await MigrationRunner.runMigrations(testDbPath);

    // Setup database
    const dbManager = DatabaseManager.getInstance();
    db = dbManager.connect(testDbPath);
    const tokenRepository = new TokenRepository(db);

    // Setup crypto service
    const cryptoService = new CryptoService(testPrivateKeyPath, testPublicKeyPath);
    await cryptoService.loadOrGenerateKeys();

    // Setup token service
    const tokenService = new TokenService(tokenRepository, cryptoService);

    // Setup Express app
    app = express();
    app.use(express.json());

    // Create controllers
    const healthController = new HealthController();
    const jwtConfig: JWTConfig = {
      privateKeyPath: testPrivateKeyPath,
      publicKeyPath: testPublicKeyPath,
      tokenExpiry: '1h',
      tokenMaxUses: 0,
    };
    const authController = new AuthController(tokenService, jwtConfig);
    const auditController = new AuditController();
    const exportController = new ExportController();

    // Mock LDAP and Azure configs for ProvidersController
    const mockLdapConfig: LDAPConfig = {
      url: 'ldap://localhost:389',
      bindDN: 'cn=admin',
      bindPassword: 'password',
      baseDN: 'dc=test,dc=com',
      tlsVerify: false,
      timeout: 30000,
    };
    const mockAzureConfig: AzureConfig = {
      enabled: false,
    };
    const providersController = new ProvidersController(mockLdapConfig, mockAzureConfig);
    const infoEndpointsConfig: InfoEndpointsConfig = {
      tokenInfoEnabled: false,
      providersInfoEnabled: false,
    };

    // Mount routes
    const routes = createRoutes(
      healthController,
      authController,
      auditController,
      exportController,
      providersController,
      tokenService,
      infoEndpointsConfig
    );
    app.use(routes);

    // Error handler must be last
    app.use(errorHandler);

    // Generate a valid token for authenticated requests
    const tokenResponse = await request(app).post('/api/v1/auth/token').send({
      name: 'test-token',
      expiresIn: 3600,
    });

    validToken = tokenResponse.body.token;
  });

  afterAll(() => {
    // Cleanup test database
    if (db) {
      db.close();
    }
    if (existsSync(testDbPath)) {
      unlinkSync(testDbPath);
    }
    // Cleanup test keys
    if (existsSync(testPrivateKeyPath)) {
      unlinkSync(testPrivateKeyPath);
    }
    if (existsSync(testPublicKeyPath)) {
      unlinkSync(testPublicKeyPath);
    }
  });

  describe('IV1: All endpoints respond with correct status codes', () => {
    it('GET /health should return 200', async () => {
      const response = await request(app).get('/health');

      expect(response.status).toBe(200);
      expect(response.body.status).toBe('healthy');
    });

    it('POST /api/v1/auth/token should return 200', async () => {
      const response = await request(app).post('/api/v1/auth/token').send({
        name: 'integration-test-token',
        expiresIn: 3600,
      });

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
      expect(response.body.token).toBeDefined();
    });

    it('POST /api/v1/auth/validate should return 200 with valid token', async () => {
      const response = await request(app)
        .post('/api/v1/auth/validate')
        .set('Authorization', `Bearer ${validToken}`)
        .send();

      expect(response.status).toBe(200);
      expect(response.body.valid).toBe(true);
    });

    it('POST /api/v1/auth/revoke should return 200', async () => {
      const response = await request(app)
        .post('/api/v1/auth/revoke')
        .set('Authorization', `Bearer ${validToken}`)
        .send();

      expect(response.status).toBe(200);
    });

    it('GET /api/v1/auth/tokens should return 200', async () => {
      const response = await request(app)
        .get('/api/v1/auth/tokens')
        .set('Authorization', `Bearer ${validToken}`);

      expect(response.status).toBe(200);
      expect(Array.isArray(response.body.tokens)).toBe(true);
    });
  });

  describe('IV2: Authentication required on protected endpoints', () => {
    it('POST /api/v1/audit/ad should require authentication', async () => {
      const response = await request(app).post('/api/v1/audit/ad').send({
        includeDetails: false,
      });

      expect(response.status).toBe(401);
      expect(response.body.success).toBe(false);
    });

    it('GET /api/v1/audit/ad/status should require authentication', async () => {
      const response = await request(app).get('/api/v1/audit/ad/status');

      expect(response.status).toBe(401);
    });

    it('POST /api/v1/audit/azure should require authentication', async () => {
      const response = await request(app).post('/api/v1/audit/azure').send({
        includeDetails: false,
      });

      expect(response.status).toBe(401);
    });

    it('GET /api/v1/audit/azure/status should require authentication', async () => {
      const response = await request(app).get('/api/v1/audit/azure/status');

      expect(response.status).toBe(401);
    });

    it('POST /api/v1/export/ad should require authentication', async () => {
      const response = await request(app).post('/api/v1/export/ad').send({
        auditResult: mockExportAuditResult,
        format: 'json',
      });

      expect(response.status).toBe(401);
    });

    it('POST /api/v1/export/azure should require authentication', async () => {
      const response = await request(app).post('/api/v1/export/azure').send({
        auditResult: mockExportAuditResult,
        format: 'json',
      });

      expect(response.status).toBe(401);
    });
  });

  describe('IV3: Rate limiting prevents abuse', () => {
    it('should enforce general API rate limit (100 req/min)', async () => {
      // Make 101 requests rapidly
      const requests = Array.from({ length: 101 }, () =>
        request(app).get('/health')
      );

      const responses = await Promise.all(requests);

      // At least one should be rate limited
      const rateLimited = responses.some((r: Response) => r.status === 429);
      expect(rateLimited).toBe(true);
    }, 30000); // 30s timeout

    it('should enforce audit rate limit (10 audits/5min)', async () => {
      // Make 11 audit requests rapidly
      const requests = Array.from({ length: 11 }, () =>
        request(app)
          .post('/api/v1/audit/ad')
          .set('Authorization', `Bearer ${validToken}`)
          .send({ includeDetails: false })
      );

      const responses = await Promise.all(requests);

      // At least one should be rate limited
      const rateLimited = responses.some((r: Response) => r.status === 429);
      expect(rateLimited).toBe(true);

      // Rate limit response should have correct error
      const rateLimitResponse = responses.find((r: Response) => r.status === 429);
      if (rateLimitResponse) {
        expect(rateLimitResponse.body.success).toBe(false);
        expect(rateLimitResponse.body.error.code).toContain('RATE_LIMIT');
      }
    }, 30000); // 30s timeout
  });

  describe('IV4: Validation rejects invalid requests', () => {
    it('POST /api/v1/audit/ad should reject invalid maxUsers', async () => {
      const response = await request(app)
        .post('/api/v1/audit/ad')
        .set('Authorization', `Bearer ${validToken}`)
        .send({
          includeDetails: false,
          maxUsers: -10, // Invalid: negative number
        });

      expect(response.status).toBe(400);
      expect(response.body.success).toBe(false);
      expect(response.body.error.code).toBe('VALIDATION_ERROR');
    });

    it('POST /api/v1/export/ad should reject invalid format', async () => {
      const response = await request(app)
        .post('/api/v1/export/ad')
        .set('Authorization', `Bearer ${validToken}`)
        .send({
          auditResult: mockExportAuditResult,
          format: 'xml', // Invalid: only json/csv allowed
        });

      expect(response.status).toBe(400);
      expect(response.body.success).toBe(false);
      expect(response.body.error.code).toBe('VALIDATION_ERROR');
    });

    it('POST /api/v1/export/ad should reject missing auditResult', async () => {
      const response = await request(app)
        .post('/api/v1/export/ad')
        .set('Authorization', `Bearer ${validToken}`)
        .send({
          format: 'json',
          // Missing auditResult
        });

      expect(response.status).toBe(400);
      expect(response.body.success).toBe(false);
      expect(response.body.error.code).toBe('VALIDATION_ERROR');
    });

    it('POST /api/v1/auth/token should reject invalid expiresIn', async () => {
      const response = await request(app).post('/api/v1/auth/token').send({
        name: 'test',
        expiresIn: 'invalid', // Invalid: not a number
      });

      expect(response.status).toBe(400);
      expect(response.body.success).toBe(false);
    });
  });

  describe('IV5: Error responses follow consistent format', () => {
    it('should return consistent error format for authentication failures', async () => {
      const response = await request(app).post('/api/v1/audit/ad').send({
        includeDetails: false,
      });

      expect(response.status).toBe(401);
      expect(response.body).toHaveProperty('success', false);
      expect(response.body).toHaveProperty('error');
      expect(response.body.error).toHaveProperty('code');
      expect(response.body.error).toHaveProperty('message');
    });

    it('should return consistent error format for validation failures', async () => {
      const response = await request(app)
        .post('/api/v1/export/ad')
        .set('Authorization', `Bearer ${validToken}`)
        .send({
          format: 'invalid-format',
        });

      expect(response.status).toBe(400);
      expect(response.body).toHaveProperty('success', false);
      expect(response.body).toHaveProperty('error');
      expect(response.body.error).toHaveProperty('code', 'VALIDATION_ERROR');
      expect(response.body.error).toHaveProperty('message');
      expect(response.body.error).toHaveProperty('details');
      expect(Array.isArray(response.body.error.details)).toBe(true);
    });

    it('should return consistent error format for rate limit failures', async () => {
      // Trigger rate limit by making many requests
      const requests = Array.from({ length: 101 }, () =>
        request(app).get('/health')
      );

      const responses = await Promise.all(requests);
      const rateLimitResponse = responses.find((r: Response) => r.status === 429);

      if (rateLimitResponse) {
        expect(rateLimitResponse.body).toHaveProperty('success', false);
        expect(rateLimitResponse.body).toHaveProperty('error');
        expect(rateLimitResponse.body.error).toHaveProperty('code');
        expect(rateLimitResponse.body.error).toHaveProperty('message');
      }
    }, 30000);
  });

  describe('Export endpoints functionality', () => {
    it('POST /api/v1/export/ad should export as JSON', async () => {
      const response = await request(app)
        .post('/api/v1/export/ad')
        .set('Authorization', `Bearer ${validToken}`)
        .send({
          auditResult: mockExportAuditResult,
          format: 'json',
          domain: 'example.com',
        });

      expect(response.status).toBe(200);
      expect(response.headers['content-type']).toContain('application/json');
      expect(response.headers['content-disposition']).toContain('attachment');
      expect(response.headers['content-disposition']).toContain('.json');
    });

    it('POST /api/v1/export/ad should export as CSV', async () => {
      const response = await request(app)
        .post('/api/v1/export/ad')
        .set('Authorization', `Bearer ${validToken}`)
        .send({
          auditResult: mockExportAuditResult,
          format: 'csv',
          domain: 'example.com',
        });

      expect(response.status).toBe(200);
      expect(response.headers['content-type']).toContain('text/csv');
      expect(response.headers['content-disposition']).toContain('attachment');
      expect(response.headers['content-disposition']).toContain('.csv');
    });

    it('POST /api/v1/export/azure should export as JSON', async () => {
      const response = await request(app)
        .post('/api/v1/export/azure')
        .set('Authorization', `Bearer ${validToken}`)
        .send({
          auditResult: mockExportAuditResult,
          format: 'json',
          tenantId: 'tenant-123',
        });

      expect(response.status).toBe(200);
      expect(response.headers['content-type']).toContain('application/json');
      expect(response.headers['content-disposition']).toContain('attachment');
    });
  });
});
