import { TokenService, GenerateTokenRequest, TokenPayload } from '../../../../src/services/auth/token.service';
import { TokenRepository } from '../../../../src/data/repositories/token.repository';
import { CryptoService } from '../../../../src/services/auth/crypto.service';
import { Token } from '../../../../src/data/models/Token.model';
import {
  TokenExpiredError,
  TokenRevokedError,
  UsageLimitExceededError,
  TokenNotFoundError,
  InvalidSignatureError,
} from '../../../../src/services/auth/errors';
import jwt from 'jsonwebtoken';

/**
 * Unit Tests for TokenService
 * Task 8: Write Unit Tests for Token Service (Story 1.4)
 */

// Mock logger first to avoid initialization errors
jest.mock('../../../../src/utils/logger', () => ({
  logger: {
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
    debug: jest.fn(),
  },
}));

// Mock uuid
jest.mock('uuid', () => ({
  v4: jest.fn(() => 'mock-uuid-v4'),
}));

// Mock dependencies
jest.mock('../../../../src/data/repositories/token.repository');
jest.mock('../../../../src/services/auth/crypto.service');
jest.mock('jsonwebtoken');

describe('TokenService', () => {
  let tokenService: TokenService;
  let mockTokenRepo: jest.Mocked<TokenRepository>;
  let mockCryptoService: jest.Mocked<CryptoService>;

  const MOCK_PRIVATE_KEY = '-----BEGIN PRIVATE KEY-----\nMOCK_KEY\n-----END PRIVATE KEY-----';
  const MOCK_PUBLIC_KEY = '-----BEGIN PUBLIC KEY-----\nMOCK_KEY\n-----END PUBLIC KEY-----';
  const MOCK_JWT_TOKEN = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.mock.signature';

  beforeEach(() => {
    // Clear all mocks
    jest.clearAllMocks();

    // Create mock instances
    mockTokenRepo = new TokenRepository({} as any) as jest.Mocked<TokenRepository>;
    mockCryptoService = new CryptoService('', '') as jest.Mocked<CryptoService>;

    // Setup default mock behaviors
    mockCryptoService.getPrivateKey.mockReturnValue(MOCK_PRIVATE_KEY);
    mockCryptoService.getPublicKey.mockReturnValue(MOCK_PUBLIC_KEY);

    // Create service with mocks
    tokenService = new TokenService(mockTokenRepo, mockCryptoService);
  });

  describe('generate', () => {
    it('should generate a valid JWT token with default options', async () => {
      // Arrange
      const options: GenerateTokenRequest = {
        expiresIn: '1h',
        maxUses: 0,
      };

      (jwt.sign as jest.Mock).mockReturnValue(MOCK_JWT_TOKEN);

      mockTokenRepo.create.mockReturnValue({
        id: 1,
        jti: 'mock-jti',
        public_key: MOCK_PUBLIC_KEY,
        created_at: new Date().toISOString(),
        expires_at: new Date(Date.now() + 3600000).toISOString(),
        max_uses: 0,
        used_count: 0,
        revoked_at: null,
        revoked_by: null,
        revoked_reason: null,
        metadata: null,
      } as Token);

      // Act
      const token = await tokenService.generate(options);

      // Assert
      expect(token).toBe(MOCK_JWT_TOKEN);
      expect(jwt.sign).toHaveBeenCalledWith(
        expect.objectContaining({
          iss: 'etc-collector',
          sub: 'system',
          service: 'etc-collector',
          maxUses: 0,
        }),
        MOCK_PRIVATE_KEY,
        { algorithm: 'RS256' }
      );
      expect(mockTokenRepo.create).toHaveBeenCalledWith(
        expect.objectContaining({
          public_key: MOCK_PUBLIC_KEY,
          max_uses: 0,
        })
      );
    });

    it('should generate token with custom maxUses', async () => {
      // Arrange
      const options: GenerateTokenRequest = {
        expiresIn: '7d',
        maxUses: 10,
      };

      (jwt.sign as jest.Mock).mockReturnValue(MOCK_JWT_TOKEN);
      mockTokenRepo.create.mockReturnValue({} as Token);

      // Act
      await tokenService.generate(options);

      // Assert
      expect(jwt.sign).toHaveBeenCalledWith(
        expect.objectContaining({
          maxUses: 10,
        }),
        MOCK_PRIVATE_KEY,
        { algorithm: 'RS256' }
      );
      expect(mockTokenRepo.create).toHaveBeenCalledWith(
        expect.objectContaining({
          max_uses: 10,
        })
      );
    });

    it('should generate token with metadata', async () => {
      // Arrange
      const metadata = { purpose: 'audit', user: 'admin' };
      const options: GenerateTokenRequest = {
        expiresIn: '1h',
        maxUses: 0,
        metadata,
      };

      (jwt.sign as jest.Mock).mockReturnValue(MOCK_JWT_TOKEN);
      mockTokenRepo.create.mockReturnValue({} as Token);

      // Act
      await tokenService.generate(options);

      // Assert
      expect(mockTokenRepo.create).toHaveBeenCalledWith(
        expect.objectContaining({
          metadata: JSON.stringify(metadata),
        })
      );
    });

    it('should parse expiry correctly: 60s → 60 seconds', async () => {
      // Arrange
      const options: GenerateTokenRequest = {
        expiresIn: '60s',
        maxUses: 0,
      };

      (jwt.sign as jest.Mock).mockReturnValue(MOCK_JWT_TOKEN);
      mockTokenRepo.create.mockReturnValue({} as Token);

      // Act
      await tokenService.generate(options);

      // Assert
      const signCall = (jwt.sign as jest.Mock).mock.calls[0];
      const payload = signCall[0] as TokenPayload;
      expect(payload.exp - payload.iat).toBe(60);
    });

    it('should parse expiry correctly: 30m → 1800 seconds', async () => {
      // Arrange
      const options: GenerateTokenRequest = {
        expiresIn: '30m',
        maxUses: 0,
      };

      (jwt.sign as jest.Mock).mockReturnValue(MOCK_JWT_TOKEN);
      mockTokenRepo.create.mockReturnValue({} as Token);

      // Act
      await tokenService.generate(options);

      // Assert
      const signCall = (jwt.sign as jest.Mock).mock.calls[0];
      const payload = signCall[0] as TokenPayload;
      expect(payload.exp - payload.iat).toBe(1800);
    });

    it('should parse expiry correctly: 1h → 3600 seconds', async () => {
      // Arrange
      const options: GenerateTokenRequest = {
        expiresIn: '1h',
        maxUses: 0,
      };

      (jwt.sign as jest.Mock).mockReturnValue(MOCK_JWT_TOKEN);
      mockTokenRepo.create.mockReturnValue({} as Token);

      // Act
      await tokenService.generate(options);

      // Assert
      const signCall = (jwt.sign as jest.Mock).mock.calls[0];
      const payload = signCall[0] as TokenPayload;
      expect(payload.exp - payload.iat).toBe(3600);
    });

    it('should parse expiry correctly: 7d → 604800 seconds', async () => {
      // Arrange
      const options: GenerateTokenRequest = {
        expiresIn: '7d',
        maxUses: 0,
      };

      (jwt.sign as jest.Mock).mockReturnValue(MOCK_JWT_TOKEN);
      mockTokenRepo.create.mockReturnValue({} as Token);

      // Act
      await tokenService.generate(options);

      // Assert
      const signCall = (jwt.sign as jest.Mock).mock.calls[0];
      const payload = signCall[0] as TokenPayload;
      expect(payload.exp - payload.iat).toBe(604800);
    });

    it('should throw error for invalid expiry format', async () => {
      // Arrange
      const options: GenerateTokenRequest = {
        expiresIn: 'invalid',
        maxUses: 0,
      };

      // Act & Assert
      await expect(tokenService.generate(options)).rejects.toThrow(
        'Invalid expiry format: invalid'
      );
    });
  });

  describe('validate', () => {
    const mockPayload: TokenPayload = {
      jti: 'test-jti',
      iss: 'etc-collector',
      sub: 'system',
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 3600,
      service: 'etc-collector',
      maxUses: 10,
    };

    const mockTokenRecord: Token = {
      id: 1,
      jti: 'test-jti',
      public_key: MOCK_PUBLIC_KEY,
      created_at: new Date().toISOString(),
      expires_at: new Date(Date.now() + 3600000).toISOString(),
      max_uses: 10,
      used_count: 5,
      revoked_at: null,
      revoked_by: null,
      revoked_reason: null,
      metadata: null,
    };

    it('should validate a valid token successfully', async () => {
      // Arrange
      (jwt.verify as jest.Mock).mockReturnValue(mockPayload);
      mockTokenRepo.findByJti.mockReturnValue(mockTokenRecord);

      // Act
      const result = await tokenService.validate(MOCK_JWT_TOKEN);

      // Assert
      expect(result).toEqual(mockPayload);
      expect(jwt.verify).toHaveBeenCalledWith(MOCK_JWT_TOKEN, MOCK_PUBLIC_KEY, {
        algorithms: ['RS256'],
      });
      expect(mockTokenRepo.findByJti).toHaveBeenCalledWith('test-jti');
    });

    it('should throw TokenExpiredError for expired token', async () => {
      // Arrange
      (jwt.verify as jest.Mock).mockImplementation(() => {
        const error = new jwt.TokenExpiredError('jwt expired', new Date());
        throw error;
      });

      // Act & Assert
      await expect(tokenService.validate(MOCK_JWT_TOKEN)).rejects.toThrow(TokenExpiredError);
    });

    it('should throw InvalidSignatureError for invalid signature', async () => {
      // Arrange
      (jwt.verify as jest.Mock).mockImplementation(() => {
        const error = new jwt.JsonWebTokenError('invalid signature');
        throw error;
      });

      // Act & Assert
      await expect(tokenService.validate(MOCK_JWT_TOKEN)).rejects.toThrow(InvalidSignatureError);
    });

    it('should throw TokenNotFoundError if jti not in database', async () => {
      // Arrange
      (jwt.verify as jest.Mock).mockReturnValue(mockPayload);
      mockTokenRepo.findByJti.mockReturnValue(null);

      // Act & Assert
      await expect(tokenService.validate(MOCK_JWT_TOKEN)).rejects.toThrow(TokenNotFoundError);
    });

    it('should throw TokenRevokedError for revoked token', async () => {
      // Arrange
      const revokedToken: Token = {
        ...mockTokenRecord,
        revoked_at: new Date().toISOString(),
        revoked_by: 'admin',
        revoked_reason: 'Security breach',
      };

      (jwt.verify as jest.Mock).mockReturnValue(mockPayload);
      mockTokenRepo.findByJti.mockReturnValue(revokedToken);

      // Act & Assert
      await expect(tokenService.validate(MOCK_JWT_TOKEN)).rejects.toThrow(TokenRevokedError);
    });

    it('should throw UsageLimitExceededError when quota exceeded', async () => {
      // Arrange
      const exhaustedToken: Token = {
        ...mockTokenRecord,
        max_uses: 10,
        used_count: 10,
      };

      (jwt.verify as jest.Mock).mockReturnValue(mockPayload);
      mockTokenRepo.findByJti.mockReturnValue(exhaustedToken);

      // Act & Assert
      await expect(tokenService.validate(MOCK_JWT_TOKEN)).rejects.toThrow(
        UsageLimitExceededError
      );
    });

    it('should allow unlimited tokens (maxUses=0) regardless of usage', async () => {
      // Arrange
      const unlimitedToken: Token = {
        ...mockTokenRecord,
        max_uses: 0,
        used_count: 1000,
      };

      (jwt.verify as jest.Mock).mockReturnValue(mockPayload);
      mockTokenRepo.findByJti.mockReturnValue(unlimitedToken);

      // Act
      const result = await tokenService.validate(MOCK_JWT_TOKEN);

      // Assert
      expect(result).toEqual(mockPayload);
    });

    it('should throw error for invalid issuer', async () => {
      // Arrange
      const invalidPayload = { ...mockPayload, iss: 'invalid-issuer' };
      (jwt.verify as jest.Mock).mockReturnValue(invalidPayload);

      // Act & Assert
      await expect(tokenService.validate(MOCK_JWT_TOKEN)).rejects.toThrow('Invalid token issuer');
    });
  });

  describe('revoke', () => {
    const mockTokenRecord: Token = {
      id: 1,
      jti: 'test-jti',
      public_key: MOCK_PUBLIC_KEY,
      created_at: new Date().toISOString(),
      expires_at: new Date(Date.now() + 3600000).toISOString(),
      max_uses: 10,
      used_count: 5,
      revoked_at: null,
      revoked_by: null,
      revoked_reason: null,
      metadata: null,
    };

    it('should revoke a token successfully', async () => {
      // Arrange
      mockTokenRepo.findByJti.mockReturnValue(mockTokenRecord);
      mockTokenRepo.revoke.mockReturnValue(undefined);

      // Act
      await tokenService.revoke('test-jti', 'admin', 'Security audit');

      // Assert
      expect(mockTokenRepo.findByJti).toHaveBeenCalledWith('test-jti');
      expect(mockTokenRepo.revoke).toHaveBeenCalledWith('test-jti', 'admin', 'Security audit');
    });

    it('should throw TokenNotFoundError if token does not exist', async () => {
      // Arrange
      mockTokenRepo.findByJti.mockReturnValue(null);

      // Act & Assert
      await expect(tokenService.revoke('nonexistent', 'admin', 'Test')).rejects.toThrow(
        TokenNotFoundError
      );
    });

    it('should be idempotent (no error if already revoked)', async () => {
      // Arrange
      const revokedToken: Token = {
        ...mockTokenRecord,
        revoked_at: new Date().toISOString(),
        revoked_by: 'admin',
      };
      mockTokenRepo.findByJti.mockReturnValue(revokedToken);

      // Act & Assert - should not throw
      await expect(
        tokenService.revoke('test-jti', 'admin', 'Test')
      ).resolves.not.toThrow();
      expect(mockTokenRepo.revoke).not.toHaveBeenCalled();
    });
  });

  describe('getInfo', () => {
    it('should return token information', async () => {
      // Arrange
      const mockTokenRecord: Token = {
        id: 1,
        jti: 'test-jti',
        public_key: MOCK_PUBLIC_KEY,
        created_at: '2026-01-12T10:00:00Z',
        expires_at: '2026-01-12T11:00:00Z',
        max_uses: 10,
        used_count: 3,
        revoked_at: null,
        revoked_by: null,
        revoked_reason: null,
        metadata: null,
      };

      mockTokenRepo.findByJti.mockReturnValue(mockTokenRecord);

      // Act
      const info = await tokenService.getInfo('test-jti');

      // Assert
      expect(info).toEqual({
        jti: 'test-jti',
        created_at: '2026-01-12T10:00:00Z',
        expires_at: '2026-01-12T11:00:00Z',
        max_uses: 10,
        used_count: 3,
        remaining_uses: 7,
        revoked: false,
        revoked_at: null,
        revoked_reason: null,
      });
    });

    it('should return -1 for remaining_uses when unlimited', async () => {
      // Arrange
      const unlimitedToken: Token = {
        id: 1,
        jti: 'test-jti',
        public_key: MOCK_PUBLIC_KEY,
        created_at: '2026-01-12T10:00:00Z',
        expires_at: '2026-01-12T11:00:00Z',
        max_uses: 0,
        used_count: 100,
        revoked_at: null,
        revoked_by: null,
        revoked_reason: null,
        metadata: null,
      };

      mockTokenRepo.findByJti.mockReturnValue(unlimitedToken);

      // Act
      const info = await tokenService.getInfo('test-jti');

      // Assert
      expect(info.remaining_uses).toBe(-1);
    });

    it('should throw TokenNotFoundError if token does not exist', async () => {
      // Arrange
      mockTokenRepo.findByJti.mockReturnValue(null);

      // Act & Assert
      await expect(tokenService.getInfo('nonexistent')).rejects.toThrow(TokenNotFoundError);
    });
  });

  describe('incrementUsage', () => {
    it('should increment token usage count', async () => {
      // Arrange
      mockTokenRepo.incrementUsage.mockReturnValue(undefined);

      // Act
      await tokenService.incrementUsage('test-jti');

      // Assert
      expect(mockTokenRepo.incrementUsage).toHaveBeenCalledWith('test-jti');
    });
  });

  describe('listAll', () => {
    it('should return array of all tokens', async () => {
      // Arrange
      const mockTokens: Token[] = [
        {
          id: 1,
          jti: 'jti-1',
          public_key: MOCK_PUBLIC_KEY,
          created_at: '2026-01-12T10:00:00Z',
          expires_at: '2026-01-12T11:00:00Z',
          max_uses: 10,
          used_count: 3,
          revoked_at: null,
          revoked_by: null,
          revoked_reason: null,
          metadata: null,
        },
        {
          id: 2,
          jti: 'jti-2',
          public_key: MOCK_PUBLIC_KEY,
          created_at: '2026-01-12T09:00:00Z',
          expires_at: '2026-01-12T10:00:00Z',
          max_uses: 0,
          used_count: 50,
          revoked_at: null,
          revoked_by: null,
          revoked_reason: null,
          metadata: null,
        },
      ];

      mockTokenRepo.findAll.mockReturnValue(mockTokens);

      // Act
      const result = await tokenService.listAll();

      // Assert
      expect(result).toHaveLength(2);
      expect(result[0]!.jti).toBe('jti-1');
      expect(result[0]!.remaining_uses).toBe(7);
      expect(result[1]!.jti).toBe('jti-2');
      expect(result[1]!.remaining_uses).toBe(-1); // Unlimited
    });

    it('should return empty array when no tokens', async () => {
      // Arrange
      mockTokenRepo.findAll.mockReturnValue([]);

      // Act
      const result = await tokenService.listAll();

      // Assert
      expect(result).toEqual([]);
    });
  });
});
