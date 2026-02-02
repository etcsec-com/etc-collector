import { Response, NextFunction } from 'express';
import { authenticate, AuthenticatedRequest } from '../../../../src/api/middlewares/authenticate';
import { TokenService } from '../../../../src/services/auth/token.service';
import {
  TokenExpiredError,
  TokenRevokedError,
  UsageLimitExceededError,
  TokenNotFoundError,
  InvalidSignatureError,
  InvalidTokenError,
} from '../../../../src/services/auth/errors';

/**
 * Unit Tests for Authentication Middleware
 * Task 10: Write Unit Tests for Authentication Middleware (Story 1.4)
 */

// Mock logger
jest.mock('../../../../src/utils/logger', () => ({
  logger: {
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
    debug: jest.fn(),
  },
}));

describe('authenticate middleware', () => {
  let mockTokenService: jest.Mocked<TokenService>;
  let middleware: ReturnType<typeof authenticate>;
  let mockReq: Partial<AuthenticatedRequest>;
  let mockRes: Partial<Response>;
  let mockNext: jest.Mock;
  let mockJson: jest.Mock;
  let mockStatus: jest.Mock;

  const VALID_TOKEN = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.mock.signature';
  const VALID_PAYLOAD = {
    jti: 'test-jti-123',
    iss: 'etc-collector',
    sub: 'system',
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 3600,
    service: 'etc-collector',
    maxUses: 10,
  };

  beforeEach(() => {
    // Create mock TokenService
    mockTokenService = {
      validate: jest.fn(),
      incrementUsage: jest.fn(),
    } as any;

    // Create middleware with mock service
    middleware = authenticate(mockTokenService);

    // Setup mock Express objects
    mockJson = jest.fn();
    mockStatus = jest.fn(() => ({ json: mockJson }));

    mockReq = {
      headers: {},
      path: '/api/v1/test',
      method: 'GET',
    };

    mockRes = {
      status: mockStatus as any,
      json: mockJson,
    };

    mockNext = jest.fn();
  });

  describe('Successful Authentication', () => {
    it('should authenticate valid token and call next()', async () => {
      // Arrange
      mockReq.headers = {
        authorization: `Bearer ${VALID_TOKEN}`,
      };

      mockTokenService.validate.mockResolvedValue(VALID_PAYLOAD);
      mockTokenService.incrementUsage.mockResolvedValue(undefined);

      // Act
      await middleware(
        mockReq as AuthenticatedRequest,
        mockRes as Response,
        mockNext as NextFunction
      );

      // Assert
      expect(mockTokenService.validate).toHaveBeenCalledWith(VALID_TOKEN);
      expect(mockTokenService.incrementUsage).toHaveBeenCalledWith(VALID_PAYLOAD.jti);
      expect(mockReq.token).toEqual({
        jti: VALID_PAYLOAD.jti,
        iat: VALID_PAYLOAD.iat,
        exp: VALID_PAYLOAD.exp,
        maxUses: VALID_PAYLOAD.maxUses,
      });
      expect(mockNext).toHaveBeenCalled();
      expect(mockStatus).not.toHaveBeenCalled();
    });

    it('should attach token info to request object', async () => {
      // Arrange
      mockReq.headers = {
        authorization: `Bearer ${VALID_TOKEN}`,
      };

      mockTokenService.validate.mockResolvedValue(VALID_PAYLOAD);
      mockTokenService.incrementUsage.mockResolvedValue(undefined);

      // Act
      await middleware(
        mockReq as AuthenticatedRequest,
        mockRes as Response,
        mockNext as NextFunction
      );

      // Assert
      expect(mockReq.token).toBeDefined();
      expect(mockReq.token!.jti).toBe(VALID_PAYLOAD.jti);
      expect(mockReq.token!.iat).toBe(VALID_PAYLOAD.iat);
      expect(mockReq.token!.exp).toBe(VALID_PAYLOAD.exp);
      expect(mockReq.token!.maxUses).toBe(VALID_PAYLOAD.maxUses);
    });

    it('should increment token usage on successful authentication', async () => {
      // Arrange
      mockReq.headers = {
        authorization: `Bearer ${VALID_TOKEN}`,
      };

      mockTokenService.validate.mockResolvedValue(VALID_PAYLOAD);
      mockTokenService.incrementUsage.mockResolvedValue(undefined);

      // Act
      await middleware(
        mockReq as AuthenticatedRequest,
        mockRes as Response,
        mockNext as NextFunction
      );

      // Assert
      expect(mockTokenService.incrementUsage).toHaveBeenCalledWith(VALID_PAYLOAD.jti);
    });
  });

  describe('Missing or Invalid Authorization Header', () => {
    it('should reject missing Authorization header with 401', async () => {
      // Arrange
      mockReq.headers = {};

      // Act
      await middleware(
        mockReq as AuthenticatedRequest,
        mockRes as Response,
        mockNext as NextFunction
      );

      // Assert
      expect(mockStatus).toHaveBeenCalledWith(401);
      expect(mockJson).toHaveBeenCalledWith({
        success: false,
        error: {
          code: 'AUTHENTICATION_FAILED',
          message: 'Missing or invalid Authorization header',
        },
      });
      expect(mockNext).not.toHaveBeenCalled();
      expect(mockTokenService.validate).not.toHaveBeenCalled();
    });

    it('should reject Authorization header without Bearer prefix', async () => {
      // Arrange
      mockReq.headers = {
        authorization: VALID_TOKEN, // Missing 'Bearer ' prefix
      };

      // Act
      await middleware(
        mockReq as AuthenticatedRequest,
        mockRes as Response,
        mockNext as NextFunction
      );

      // Assert
      expect(mockStatus).toHaveBeenCalledWith(401);
      expect(mockJson).toHaveBeenCalledWith({
        success: false,
        error: {
          code: 'AUTHENTICATION_FAILED',
          message: 'Missing or invalid Authorization header',
        },
      });
      expect(mockNext).not.toHaveBeenCalled();
    });

    it('should reject Authorization header with wrong scheme', async () => {
      // Arrange
      mockReq.headers = {
        authorization: `Basic ${VALID_TOKEN}`, // Wrong scheme
      };

      // Act
      await middleware(
        mockReq as AuthenticatedRequest,
        mockRes as Response,
        mockNext as NextFunction
      );

      // Assert
      expect(mockStatus).toHaveBeenCalledWith(401);
      expect(mockNext).not.toHaveBeenCalled();
    });
  });

  describe('Expired Token', () => {
    it('should reject expired token with 401 TOKEN_EXPIRED', async () => {
      // Arrange
      mockReq.headers = {
        authorization: `Bearer ${VALID_TOKEN}`,
      };

      mockTokenService.validate.mockRejectedValue(new TokenExpiredError());

      // Act
      await middleware(
        mockReq as AuthenticatedRequest,
        mockRes as Response,
        mockNext as NextFunction
      );

      // Assert
      expect(mockStatus).toHaveBeenCalledWith(401);
      expect(mockJson).toHaveBeenCalledWith({
        success: false,
        error: {
          code: 'TOKEN_EXPIRED',
          message: 'Token has expired',
        },
      });
      expect(mockNext).not.toHaveBeenCalled();
      expect(mockTokenService.incrementUsage).not.toHaveBeenCalled();
    });
  });

  describe('Revoked Token', () => {
    it('should reject revoked token with 401 TOKEN_REVOKED', async () => {
      // Arrange
      mockReq.headers = {
        authorization: `Bearer ${VALID_TOKEN}`,
      };

      mockTokenService.validate.mockRejectedValue(new TokenRevokedError());

      // Act
      await middleware(
        mockReq as AuthenticatedRequest,
        mockRes as Response,
        mockNext as NextFunction
      );

      // Assert
      expect(mockStatus).toHaveBeenCalledWith(401);
      expect(mockJson).toHaveBeenCalledWith({
        success: false,
        error: {
          code: 'TOKEN_REVOKED',
          message: 'Token has been revoked',
        },
      });
      expect(mockNext).not.toHaveBeenCalled();
      expect(mockTokenService.incrementUsage).not.toHaveBeenCalled();
    });
  });

  describe('Usage Limit Exceeded', () => {
    it('should reject token with quota exceeded with 403 USAGE_LIMIT_EXCEEDED', async () => {
      // Arrange
      mockReq.headers = {
        authorization: `Bearer ${VALID_TOKEN}`,
      };

      mockTokenService.validate.mockRejectedValue(new UsageLimitExceededError());

      // Act
      await middleware(
        mockReq as AuthenticatedRequest,
        mockRes as Response,
        mockNext as NextFunction
      );

      // Assert
      expect(mockStatus).toHaveBeenCalledWith(403);
      expect(mockJson).toHaveBeenCalledWith({
        success: false,
        error: {
          code: 'USAGE_LIMIT_EXCEEDED',
          message: 'Token usage limit exceeded',
        },
      });
      expect(mockNext).not.toHaveBeenCalled();
      expect(mockTokenService.incrementUsage).not.toHaveBeenCalled();
    });
  });

  describe('Token Not Found', () => {
    it('should reject token not in database with 401 AUTHENTICATION_FAILED', async () => {
      // Arrange
      mockReq.headers = {
        authorization: `Bearer ${VALID_TOKEN}`,
      };

      mockTokenService.validate.mockRejectedValue(new TokenNotFoundError());

      // Act
      await middleware(
        mockReq as AuthenticatedRequest,
        mockRes as Response,
        mockNext as NextFunction
      );

      // Assert
      expect(mockStatus).toHaveBeenCalledWith(401);
      expect(mockJson).toHaveBeenCalledWith({
        success: false,
        error: {
          code: 'AUTHENTICATION_FAILED',
          message: 'Invalid token',
        },
      });
      expect(mockNext).not.toHaveBeenCalled();
    });
  });

  describe('Invalid Signature', () => {
    it('should reject token with invalid signature with 401', async () => {
      // Arrange
      mockReq.headers = {
        authorization: `Bearer ${VALID_TOKEN}`,
      };

      mockTokenService.validate.mockRejectedValue(new InvalidSignatureError());

      // Act
      await middleware(
        mockReq as AuthenticatedRequest,
        mockRes as Response,
        mockNext as NextFunction
      );

      // Assert
      expect(mockStatus).toHaveBeenCalledWith(401);
      expect(mockJson).toHaveBeenCalledWith({
        success: false,
        error: {
          code: 'AUTHENTICATION_FAILED',
          message: 'Invalid token signature',
        },
      });
      expect(mockNext).not.toHaveBeenCalled();
    });
  });

  describe('Invalid Token', () => {
    it('should reject malformed token with 401', async () => {
      // Arrange
      mockReq.headers = {
        authorization: `Bearer ${VALID_TOKEN}`,
      };

      mockTokenService.validate.mockRejectedValue(new InvalidTokenError());

      // Act
      await middleware(
        mockReq as AuthenticatedRequest,
        mockRes as Response,
        mockNext as NextFunction
      );

      // Assert
      expect(mockStatus).toHaveBeenCalledWith(401);
      expect(mockJson).toHaveBeenCalledWith({
        success: false,
        error: {
          code: 'AUTHENTICATION_FAILED',
          message: 'Invalid token',
        },
      });
      expect(mockNext).not.toHaveBeenCalled();
    });
  });

  describe('Unexpected Errors', () => {
    it('should handle unexpected error with generic 401', async () => {
      // Arrange
      mockReq.headers = {
        authorization: `Bearer ${VALID_TOKEN}`,
      };

      mockTokenService.validate.mockRejectedValue(new Error('Unexpected error'));

      // Act
      await middleware(
        mockReq as AuthenticatedRequest,
        mockRes as Response,
        mockNext as NextFunction
      );

      // Assert
      expect(mockStatus).toHaveBeenCalledWith(401);
      expect(mockJson).toHaveBeenCalledWith({
        success: false,
        error: {
          code: 'AUTHENTICATION_FAILED',
          message: 'Authentication failed',
        },
      });
      expect(mockNext).not.toHaveBeenCalled();
    });
  });

  describe('Error Response Format', () => {
    it('should always return consistent error format', async () => {
      // Arrange
      mockReq.headers = {};

      // Act
      await middleware(
        mockReq as AuthenticatedRequest,
        mockRes as Response,
        mockNext as NextFunction
      );

      // Assert
      const errorResponse = mockJson.mock.calls[0][0];
      expect(errorResponse).toHaveProperty('success', false);
      expect(errorResponse).toHaveProperty('error');
      expect(errorResponse.error).toHaveProperty('code');
      expect(errorResponse.error).toHaveProperty('message');
    });
  });
});
