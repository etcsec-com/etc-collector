import { LDAPProvider } from '../../../../src/providers/ldap/ldap.provider';
import { LDAPClient } from '../../../../src/providers/ldap/ldap-client';
import { LDAPConfig } from '../../../../src/types/config.types';
import { Entry } from 'ldapts';

/**
 * Unit Tests for LDAP Provider
 * Task 8: Write Unit Tests for LDAP Provider (Story 1.5)
 */

// Mock LDAPClient
jest.mock('../../../../src/providers/ldap/ldap-client');

// Mock logger
jest.mock('../../../../src/utils/logger', () => ({
  logger: {
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
    debug: jest.fn(),
  },
}));

describe('LDAPProvider', () => {
  let mockClient: jest.Mocked<LDAPClient>;
  let provider: LDAPProvider;
  let config: LDAPConfig;

  beforeEach(() => {
    jest.clearAllMocks();

    config = {
      url: 'ldaps://dc.example.com:636',
      bindDN: 'cn=admin,dc=example,dc=com',
      bindPassword: 'password',
      baseDN: 'dc=example,dc=com',
      tlsVerify: true,
      timeout: 5000,
    };

    // Create provider instance
    provider = new LDAPProvider(config);

    // Get mock client instance
    mockClient = jest.mocked(LDAPClient).mock.instances[0] as jest.Mocked<LDAPClient>;
    mockClient.connect = jest.fn().mockResolvedValue(undefined);
    mockClient.disconnect = jest.fn().mockResolvedValue(undefined);
    mockClient.testConnection = jest.fn().mockResolvedValue({ success: true, responseTime: 100 });
    mockClient.search = jest.fn().mockResolvedValue([]);
  });

  describe('constructor', () => {
    it('should create LDAPClient with correct options', () => {
      expect(LDAPClient).toHaveBeenCalledWith({
        url: 'ldaps://dc.example.com:636',
        bindDN: 'cn=admin,dc=example,dc=com',
        bindPassword: 'password',
        timeout: 5000,
        tlsOptions: {
          rejectUnauthorized: true,
        },
      });
    });
  });

  describe('connect', () => {
    it('should call client connect', async () => {
      await provider.connect();

      expect(mockClient.connect).toHaveBeenCalled();
    });
  });

  describe('disconnect', () => {
    it('should call client disconnect', async () => {
      await provider.disconnect();

      expect(mockClient.disconnect).toHaveBeenCalled();
    });
  });

  describe('testConnection', () => {
    it('should return success result with details', async () => {
      mockClient.testConnection.mockResolvedValue({ success: true, responseTime: 150 });

      const result = await provider.testConnection();

      expect(result.success).toBe(true);
      expect(result.message).toBe('Connection successful');
      expect(result.details).toBeDefined();
      expect(result.details?.url).toBe('ldaps://dc.example.com:636');
      expect(result.details?.baseDN).toBe('dc=example,dc=com');
      expect(result.details?.protocol).toBe('ldaps');
      expect(result.details?.bindDN).toBe('cn=admin,dc=example,dc=com');
      expect(result.details?.responseTime).toBe(150);
    });

    it('should detect ldap protocol', async () => {
      const ldapConfig: LDAPConfig = {
        ...config,
        url: 'ldap://dc.example.com:389',
      };

      const ldapProvider = new LDAPProvider(ldapConfig);

      // Get the new mock client instance
      const newMockClient = jest.mocked(LDAPClient).mock.instances[1] as jest.Mocked<LDAPClient>;
      newMockClient.testConnection = jest.fn().mockResolvedValue({ success: true, responseTime: 100 });

      const result = await ldapProvider.testConnection();

      expect(result.details?.protocol).toBe('ldap');
    });

    it('should return failure result', async () => {
      mockClient.testConnection.mockResolvedValue({ success: false, responseTime: 5000 });

      const result = await provider.testConnection();

      expect(result.success).toBe(false);
      expect(result.message).toBe('Connection failed');
      expect(result.details).toBeUndefined();
    });
  });

  describe('searchUsers', () => {
    it('should search for all users with default filter', async () => {
      const mockEntries: Entry[] = [
        {
          dn: 'cn=John Doe,ou=Users,dc=example,dc=com',
          sAMAccountName: 'jdoe',
          userPrincipalName: 'jdoe@example.com',
        },
      ];

      mockClient.search.mockResolvedValue(mockEntries);

      const users = await provider.searchUsers();

      expect(mockClient.search).toHaveBeenCalledWith('dc=example,dc=com', {
        filter: '(&(objectClass=user)(objectCategory=person))',
        scope: 'sub',
        attributes: expect.arrayContaining(['sAMAccountName', 'userPrincipalName']),
        paged: true,
      });

      expect(users).toHaveLength(1);
      expect(users[0]?.sAMAccountName).toBe('jdoe');
    });

    it('should search with custom filter', async () => {
      const mockEntries: Entry[] = [];
      mockClient.search.mockResolvedValue(mockEntries);

      await provider.searchUsers('(sAMAccountName=admin*)');

      expect(mockClient.search).toHaveBeenCalledWith('dc=example,dc=com', {
        filter: '(&(objectClass=user)(objectCategory=person)(sAMAccountName=admin*))',
        scope: 'sub',
        attributes: expect.any(Array),
        paged: true,
      });
    });

    it('should search with custom attributes', async () => {
      const mockEntries: Entry[] = [];
      mockClient.search.mockResolvedValue(mockEntries);

      await provider.searchUsers(undefined, ['dn', 'sAMAccountName']);

      expect(mockClient.search).toHaveBeenCalledWith('dc=example,dc=com', {
        filter: expect.any(String),
        scope: 'sub',
        attributes: ['dn', 'sAMAccountName'],
        paged: true,
      });
    });
  });

  describe('searchGroups', () => {
    it('should search for all groups with default filter', async () => {
      const mockEntries: Entry[] = [
        {
          dn: 'cn=Admins,ou=Groups,dc=example,dc=com',
          sAMAccountName: 'Admins',
        },
      ];

      mockClient.search.mockResolvedValue(mockEntries);

      const groups = await provider.searchGroups();

      expect(mockClient.search).toHaveBeenCalledWith('dc=example,dc=com', {
        filter: '(objectClass=group)',
        scope: 'sub',
        attributes: expect.arrayContaining(['sAMAccountName', 'member']),
        paged: true,
      });

      expect(groups).toHaveLength(1);
      expect(groups[0]?.sAMAccountName).toBe('Admins');
    });

    it('should search with custom filter', async () => {
      const mockEntries: Entry[] = [];
      mockClient.search.mockResolvedValue(mockEntries);

      await provider.searchGroups('(sAMAccountName=Domain*)');

      expect(mockClient.search).toHaveBeenCalledWith('dc=example,dc=com', {
        filter: '(&(objectClass=group)(sAMAccountName=Domain*))',
        scope: 'sub',
        attributes: expect.any(Array),
        paged: true,
      });
    });
  });

  describe('searchComputers', () => {
    it('should search for all computers with default filter', async () => {
      const mockEntries: Entry[] = [
        {
          dn: 'cn=WORKSTATION1,ou=Computers,dc=example,dc=com',
          sAMAccountName: 'WORKSTATION1$',
        },
      ];

      mockClient.search.mockResolvedValue(mockEntries);

      const computers = await provider.searchComputers();

      expect(mockClient.search).toHaveBeenCalledWith('dc=example,dc=com', {
        filter: '(objectClass=computer)',
        scope: 'sub',
        attributes: expect.arrayContaining(['sAMAccountName', 'dNSHostName']),
        paged: true,
      });

      expect(computers).toHaveLength(1);
      expect(computers[0]?.sAMAccountName).toBe('WORKSTATION1$');
    });

    it('should search with custom filter', async () => {
      const mockEntries: Entry[] = [];
      mockClient.search.mockResolvedValue(mockEntries);

      await provider.searchComputers('(operatingSystem=Windows 10*)');

      expect(mockClient.search).toHaveBeenCalledWith('dc=example,dc=com', {
        filter: '(&(objectClass=computer)(operatingSystem=Windows 10*))',
        scope: 'sub',
        attributes: expect.any(Array),
        paged: true,
      });
    });
  });

  describe('searchOUs', () => {
    it('should search for all OUs with default filter', async () => {
      const mockEntries: Entry[] = [
        {
          dn: 'ou=Users,dc=example,dc=com',
          name: 'Users',
        },
      ];

      mockClient.search.mockResolvedValue(mockEntries);

      const ous = await provider.searchOUs();

      expect(mockClient.search).toHaveBeenCalledWith('dc=example,dc=com', {
        filter: '(objectClass=organizationalUnit)',
        scope: 'sub',
        attributes: expect.arrayContaining(['dn', 'name']),
        paged: true,
      });

      expect(ous).toHaveLength(1);
      expect(ous[0]?.name).toBe('Users');
    });

    it('should search with custom filter', async () => {
      const mockEntries: Entry[] = [];
      mockClient.search.mockResolvedValue(mockEntries);

      await provider.searchOUs('(description=*)');

      expect(mockClient.search).toHaveBeenCalledWith('dc=example,dc=com', {
        filter: '(&(objectClass=organizationalUnit)(description=*))',
        scope: 'sub',
        attributes: expect.any(Array),
        paged: true,
      });
    });
  });

  describe('search (generic)', () => {
    it('should perform generic search with valid filter', async () => {
      const mockEntries: Entry[] = [
        {
          dn: 'cn=Object,dc=example,dc=com',
          attr: 'value',
        },
      ];

      mockClient.search.mockResolvedValue(mockEntries);

      const results = await provider.search('dc=example,dc=com', {
        filter: '(objectClass=*)',
        scope: 'sub',
      });

      expect(mockClient.search).toHaveBeenCalledWith('dc=example,dc=com', {
        filter: '(objectClass=*)',
        scope: 'sub',
      });

      expect(results).toHaveLength(1);
    });

    it('should throw error for invalid filter syntax', async () => {
      await expect(
        provider.search('dc=example,dc=com', {
          filter: 'invalid-filter',
          scope: 'sub',
        })
      ).rejects.toThrow('Invalid LDAP filter syntax');
    });

    it('should throw error for invalid DN', async () => {
      await expect(
        provider.search('invalid-dn', {
          filter: '(objectClass=*)',
          scope: 'sub',
        })
      ).rejects.toThrow('Invalid LDAP DN');
    });
  });

  describe('buildSafeFilter', () => {
    it('should build safe filter with sanitized value', () => {
      const filter = provider.buildSafeFilter('uid', '=', 'user*');

      expect(filter).toBe('(uid=user\\2a)');
    });

    it('should build filter with various operators', () => {
      expect(provider.buildSafeFilter('age', '>=', '18')).toBe('(age>=18)');
      expect(provider.buildSafeFilter('age', '<=', '65')).toBe('(age<=65)');
      expect(provider.buildSafeFilter('name', '~=', 'john')).toBe('(name~=john)');
    });
  });

  describe('buildLogicalFilter', () => {
    it('should build AND filter', () => {
      const filter = provider.buildLogicalFilter('&', [
        '(uid=john)',
        '(objectClass=person)',
      ]);

      expect(filter).toBe('(&(uid=john)(objectClass=person))');
    });

    it('should build OR filter', () => {
      const filter = provider.buildLogicalFilter('|', ['(uid=john)', '(uid=jane)']);

      expect(filter).toBe('(|(uid=john)(uid=jane))');
    });

    it('should build NOT filter', () => {
      const filter = provider.buildLogicalFilter('!', ['(uid=admin)']);

      expect(filter).toBe('(!(uid=admin))');
    });
  });
});
