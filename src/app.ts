import express, { Express } from 'express';
import helmet from 'helmet';
import cors from 'cors';
import swaggerUi from 'swagger-ui-express';
import yaml from 'js-yaml';
import fs from 'fs';
import path from 'path';
import { DIContainer } from './container';
import { createRoutes } from './api/routes';
import { apiLimiter } from './api/middlewares/rateLimit';
import { errorHandler } from './api/middlewares/errorHandler';

/**
 * Express Application Setup
 * Configures middleware and mounts routes
 */
export function createApp(): Express {
  const app = express();

  // Security middleware (skip helmet for swagger)
  app.use((req, res, next) => {
    if (req.path.startsWith('/swagger')) {
      return next();
    }
    helmet()(req, res, next);
  });
  app.use(cors());

  // Body parsing
  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));

  // Rate limiting
  app.use('/api/', apiLimiter);

  // Swagger UI - load OpenAPI spec (MUST be before other routes)
  try {
    const openapiPath = path.join(__dirname, '../docs/api/openapi.yaml');
    const openapiSpec = yaml.load(fs.readFileSync(openapiPath, 'utf8')) as object;
    app.use('/swagger', swaggerUi.serve, swaggerUi.setup(openapiSpec, {
      customCss: '.swagger-ui .topbar { display: none }',
      customSiteTitle: 'ETC Collector API',
    }));
  } catch (err) {
    console.error('Failed to load Swagger:', err);
  }

  // Get controllers and services from DI container
  const container = DIContainer.getInstance();
  const healthController = container.getHealthController();
  const authController = container.getAuthController();
  const auditController = container.getAuditController();
  const exportController = container.getExportController();
  const providersController = container.getProvidersController();
  const tokenService = container.getTokenService();
  const infoEndpointsConfig = container.getInfoEndpointsConfig();

  // Mount routes
  app.use(
    '/',
    createRoutes(
      healthController,
      authController,
      auditController,
      exportController,
      providersController,
      tokenService,
      infoEndpointsConfig
    )
  );

  // 404 handler
  app.use((_req, res) => {
    res.status(404).json({
      success: false,
      error: {
        code: 'NOT_FOUND',
        message: 'The requested resource was not found',
      },
    });
  });

  // Error handler (must be last)
  app.use(errorHandler);

  return app;
}
