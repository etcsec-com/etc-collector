import { CryptoService } from '../../../../src/services/auth/crypto.service';
import { existsSync, readFileSync, writeFileSync, chmodSync, mkdirSync } from 'fs';
import crypto from 'crypto';

/**
 * Unit Tests for CryptoService
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

// Mock fs module
jest.mock('fs');
jest.mock('crypto');

describe('CryptoService', () => {
  let cryptoService: CryptoService;
  const mockPrivateKeyPath = '/mock/keys/private.pem';
  const mockPublicKeyPath = '/mock/keys/public.pem';

  const MOCK_PRIVATE_KEY = '-----BEGIN PRIVATE KEY-----\nMOCK_PRIVATE_KEY\n-----END PRIVATE KEY-----';
  const MOCK_PUBLIC_KEY = '-----BEGIN PUBLIC KEY-----\nMOCK_PUBLIC_KEY\n-----END PUBLIC KEY-----';

  beforeEach(() => {
    jest.clearAllMocks();
    cryptoService = new CryptoService(mockPrivateKeyPath, mockPublicKeyPath);
  });

  describe('generateKeyPair', () => {
    it('should generate RSA key pair with correct specifications', () => {
      // Arrange
      const mockKeyPair = {
        privateKey: MOCK_PRIVATE_KEY,
        publicKey: MOCK_PUBLIC_KEY,
      };

      (crypto.generateKeyPairSync as jest.Mock).mockReturnValue(mockKeyPair);

      // Act
      const result = cryptoService.generateKeyPair();

      // Assert
      expect(crypto.generateKeyPairSync).toHaveBeenCalledWith('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: {
          type: 'spki',
          format: 'pem',
        },
        privateKeyEncoding: {
          type: 'pkcs8',
          format: 'pem',
        },
      });
      expect(result).toEqual(mockKeyPair);
    });
  });

  describe('loadOrGenerateKeys', () => {
    it('should load existing keys from filesystem', async () => {
      // Arrange
      (existsSync as jest.Mock).mockReturnValue(true);
      (readFileSync as jest.Mock)
        .mockReturnValueOnce(MOCK_PRIVATE_KEY)
        .mockReturnValueOnce(MOCK_PUBLIC_KEY);

      // Act
      await cryptoService.loadOrGenerateKeys();

      // Assert
      expect(existsSync).toHaveBeenCalledWith(mockPrivateKeyPath);
      expect(existsSync).toHaveBeenCalledWith(mockPublicKeyPath);
      expect(readFileSync).toHaveBeenCalledWith(mockPrivateKeyPath, 'utf-8');
      expect(readFileSync).toHaveBeenCalledWith(mockPublicKeyPath, 'utf-8');
      expect(cryptoService.getPrivateKey()).toBe(MOCK_PRIVATE_KEY);
      expect(cryptoService.getPublicKey()).toBe(MOCK_PUBLIC_KEY);
    });

    it('should generate new keys if they do not exist', async () => {
      // Arrange
      (existsSync as jest.Mock).mockReturnValue(false);
      (crypto.generateKeyPairSync as jest.Mock).mockReturnValue({
        privateKey: MOCK_PRIVATE_KEY,
        publicKey: MOCK_PUBLIC_KEY,
      });
      (mkdirSync as jest.Mock).mockReturnValue(undefined);
      (writeFileSync as jest.Mock).mockReturnValue(undefined);
      (chmodSync as jest.Mock).mockReturnValue(undefined);

      // Act
      await cryptoService.loadOrGenerateKeys();

      // Assert
      expect(crypto.generateKeyPairSync).toHaveBeenCalled();
      expect(writeFileSync).toHaveBeenCalledWith(
        mockPrivateKeyPath,
        MOCK_PRIVATE_KEY,
        { mode: 0o600 }
      );
      expect(writeFileSync).toHaveBeenCalledWith(
        mockPublicKeyPath,
        MOCK_PUBLIC_KEY,
        { mode: 0o644 }
      );
      expect(chmodSync).toHaveBeenCalledWith(mockPrivateKeyPath, 0o600);
      expect(chmodSync).toHaveBeenCalledWith(mockPublicKeyPath, 0o644);
    });

    it('should regenerate both keys if only one exists', async () => {
      // Arrange
      (existsSync as jest.Mock)
        .mockReturnValueOnce(true)  // privateKey exists
        .mockReturnValueOnce(false); // publicKey doesn't exist

      (crypto.generateKeyPairSync as jest.Mock).mockReturnValue({
        privateKey: MOCK_PRIVATE_KEY,
        publicKey: MOCK_PUBLIC_KEY,
      });
      (mkdirSync as jest.Mock).mockReturnValue(undefined);
      (writeFileSync as jest.Mock).mockReturnValue(undefined);
      (chmodSync as jest.Mock).mockReturnValue(undefined);

      // Act
      await cryptoService.loadOrGenerateKeys();

      // Assert
      expect(crypto.generateKeyPairSync).toHaveBeenCalled();
      expect(writeFileSync).toHaveBeenCalledTimes(2);
    });

    it('should throw error if key loading fails', async () => {
      // Arrange
      (existsSync as jest.Mock).mockReturnValue(true);
      (readFileSync as jest.Mock).mockImplementation(() => {
        throw new Error('File read error');
      });

      // Act & Assert
      await expect(cryptoService.loadOrGenerateKeys()).rejects.toThrow(
        'Failed to load RSA keys: File read error'
      );
    });

    it('should throw error if key generation fails', async () => {
      // Arrange
      (existsSync as jest.Mock).mockReturnValue(false);
      (crypto.generateKeyPairSync as jest.Mock).mockImplementation(() => {
        throw new Error('Generation failed');
      });

      // Act & Assert
      await expect(cryptoService.loadOrGenerateKeys()).rejects.toThrow(
        'Failed to generate RSA keys: Generation failed'
      );
    });

    it('should validate key format when loading', async () => {
      // Arrange - Invalid private key format
      const invalidKey = 'INVALID_KEY_NO_MARKERS';
      (existsSync as jest.Mock).mockReturnValue(true);
      (readFileSync as jest.Mock)
        .mockReturnValueOnce(invalidKey)
        .mockReturnValueOnce(MOCK_PUBLIC_KEY);

      // Act & Assert
      await expect(cryptoService.loadOrGenerateKeys()).rejects.toThrow(
        'Invalid PRIVATE KEY format: missing PEM markers'
      );
    });
  });

  describe('getPrivateKey', () => {
    it('should return private key after loading', async () => {
      // Arrange
      (existsSync as jest.Mock).mockReturnValue(true);
      (readFileSync as jest.Mock)
        .mockReturnValueOnce(MOCK_PRIVATE_KEY)
        .mockReturnValueOnce(MOCK_PUBLIC_KEY);

      await cryptoService.loadOrGenerateKeys();

      // Act
      const privateKey = cryptoService.getPrivateKey();

      // Assert
      expect(privateKey).toBe(MOCK_PRIVATE_KEY);
    });

    it('should throw error if keys not loaded', () => {
      // Act & Assert
      expect(() => cryptoService.getPrivateKey()).toThrow(
        'Keys not loaded. Call loadOrGenerateKeys() first.'
      );
    });
  });

  describe('getPublicKey', () => {
    it('should return public key after loading', async () => {
      // Arrange
      (existsSync as jest.Mock).mockReturnValue(true);
      (readFileSync as jest.Mock)
        .mockReturnValueOnce(MOCK_PRIVATE_KEY)
        .mockReturnValueOnce(MOCK_PUBLIC_KEY);

      await cryptoService.loadOrGenerateKeys();

      // Act
      const publicKey = cryptoService.getPublicKey();

      // Assert
      expect(publicKey).toBe(MOCK_PUBLIC_KEY);
    });

    it('should throw error if keys not loaded', () => {
      // Act & Assert
      expect(() => cryptoService.getPublicKey()).toThrow(
        'Keys not loaded. Call loadOrGenerateKeys() first.'
      );
    });
  });

  describe('file permissions', () => {
    it('should set private key permissions to 600', async () => {
      // Arrange
      (existsSync as jest.Mock).mockReturnValue(false);
      (crypto.generateKeyPairSync as jest.Mock).mockReturnValue({
        privateKey: MOCK_PRIVATE_KEY,
        publicKey: MOCK_PUBLIC_KEY,
      });
      (mkdirSync as jest.Mock).mockReturnValue(undefined);
      (writeFileSync as jest.Mock).mockReturnValue(undefined);
      (chmodSync as jest.Mock).mockReturnValue(undefined);

      // Act
      await cryptoService.loadOrGenerateKeys();

      // Assert
      expect(writeFileSync).toHaveBeenCalledWith(
        mockPrivateKeyPath,
        MOCK_PRIVATE_KEY,
        { mode: 0o600 }
      );
      expect(chmodSync).toHaveBeenCalledWith(mockPrivateKeyPath, 0o600);
    });

    it('should set public key permissions to 644', async () => {
      // Arrange
      (existsSync as jest.Mock).mockReturnValue(false);
      (crypto.generateKeyPairSync as jest.Mock).mockReturnValue({
        privateKey: MOCK_PRIVATE_KEY,
        publicKey: MOCK_PUBLIC_KEY,
      });
      (mkdirSync as jest.Mock).mockReturnValue(undefined);
      (writeFileSync as jest.Mock).mockReturnValue(undefined);
      (chmodSync as jest.Mock).mockReturnValue(undefined);

      // Act
      await cryptoService.loadOrGenerateKeys();

      // Assert
      expect(writeFileSync).toHaveBeenCalledWith(
        mockPublicKeyPath,
        MOCK_PUBLIC_KEY,
        { mode: 0o644 }
      );
      expect(chmodSync).toHaveBeenCalledWith(mockPublicKeyPath, 0o644);
    });
  });

  describe('directory creation', () => {
    it('should create parent directories if they do not exist', async () => {
      // Arrange
      (existsSync as jest.Mock).mockReturnValue(false);
      (crypto.generateKeyPairSync as jest.Mock).mockReturnValue({
        privateKey: MOCK_PRIVATE_KEY,
        publicKey: MOCK_PUBLIC_KEY,
      });
      (mkdirSync as jest.Mock).mockReturnValue(undefined);
      (writeFileSync as jest.Mock).mockReturnValue(undefined);
      (chmodSync as jest.Mock).mockReturnValue(undefined);

      // Act
      await cryptoService.loadOrGenerateKeys();

      // Assert
      expect(mkdirSync).toHaveBeenCalledWith('/mock/keys', { recursive: true });
    });
  });
});
