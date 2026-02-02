import { Entry } from 'ldapts';
import {
  mapToADUser,
  mapToADGroup,
  mapToADComputer,
  mapToADOU,
  mapToGeneric,
} from '../../../../src/providers/ldap/ad-mappers';

/**
 * Unit Tests for AD Type Mappers
 * Task 8: Write Unit Tests for LDAP Provider (Story 1.5)
 */

describe('AD Mappers', () => {
  describe('mapToADUser', () => {
    it('should map basic LDAP entry to ADUser', () => {
      const entry: Entry = {
        dn: 'cn=John Doe,ou=Users,dc=example,dc=com',
        sAMAccountName: 'jdoe',
        userPrincipalName: 'jdoe@example.com',
        displayName: 'John Doe',
        userAccountControl: '512', // Enabled account
      };

      const result = mapToADUser(entry);

      expect(result.dn).toBe('cn=John Doe,ou=Users,dc=example,dc=com');
      expect(result.sAMAccountName).toBe('jdoe');
      expect(result.userPrincipalName).toBe('jdoe@example.com');
      expect(result.displayName).toBe('John Doe');
      expect(result.enabled).toBe(true);
      expect(result.userAccountControl).toBe(512);
    });

    it('should map disabled account correctly', () => {
      const entry: Entry = {
        dn: 'cn=Disabled User,ou=Users,dc=example,dc=com',
        sAMAccountName: 'disabled',
        userAccountControl: '514', // Disabled account (512 + 2)
      };

      const result = mapToADUser(entry);

      expect(result.enabled).toBe(false);
      expect(result.userAccountControl).toBe(514);
    });

    it('should handle missing optional fields', () => {
      const entry: Entry = {
        dn: 'cn=Minimal User,ou=Users,dc=example,dc=com',
        sAMAccountName: 'minimal',
      };

      const result = mapToADUser(entry);

      expect(result.sAMAccountName).toBe('minimal');
      expect(result.userPrincipalName).toBeUndefined();
      expect(result.displayName).toBeUndefined();
      expect(result.passwordLastSet).toBeUndefined();
      expect(result.lastLogon).toBeUndefined();
      expect(result.adminCount).toBeUndefined();
    });

    it('should map memberOf array', () => {
      const entry: Entry = {
        dn: 'cn=User,ou=Users,dc=example,dc=com',
        sAMAccountName: 'user',
        memberOf: ['cn=Group1,ou=Groups,dc=example,dc=com', 'cn=Group2,ou=Groups,dc=example,dc=com'],
      };

      const result = mapToADUser(entry);

      expect(result.memberOf).toHaveLength(2);
      expect(result.memberOf).toContain('cn=Group1,ou=Groups,dc=example,dc=com');
      expect(result.memberOf).toContain('cn=Group2,ou=Groups,dc=example,dc=com');
    });

    it('should convert Windows FILETIME for passwordLastSet', () => {
      const entry: Entry = {
        dn: 'cn=User,ou=Users,dc=example,dc=com',
        sAMAccountName: 'user',
        pwdLastSet: '132850000000000000', // Valid FILETIME
      };

      const result = mapToADUser(entry);

      expect(result.passwordLastSet).toBeInstanceOf(Date);
      expect(result.passwordLastSet).toBeDefined();
    });

    it('should handle zero FILETIME as undefined', () => {
      const entry: Entry = {
        dn: 'cn=User,ou=Users,dc=example,dc=com',
        sAMAccountName: 'user',
        pwdLastSet: '0',
      };

      const result = mapToADUser(entry);

      expect(result.passwordLastSet).toBeUndefined();
    });

    it('should include extra attributes in user object', () => {
      const entry: Entry = {
        dn: 'cn=User,ou=Users,dc=example,dc=com',
        sAMAccountName: 'user',
        customAttribute: 'customValue',
        mail: 'user@example.com',
      };

      const result = mapToADUser(entry);

      expect(result['customAttribute']).toBe('customValue');
      expect(result['mail']).toBe('user@example.com');
    });

    it('should default to enabled if userAccountControl is missing', () => {
      const entry: Entry = {
        dn: 'cn=User,ou=Users,dc=example,dc=com',
        sAMAccountName: 'user',
      };

      const result = mapToADUser(entry);

      expect(result.enabled).toBe(true);
    });

    it('should handle adminCount attribute', () => {
      const entry: Entry = {
        dn: 'cn=Admin,ou=Users,dc=example,dc=com',
        sAMAccountName: 'admin',
        adminCount: '1',
      };

      const result = mapToADUser(entry);

      expect(result.adminCount).toBe(1);
    });
  });

  describe('mapToADGroup', () => {
    it('should map basic LDAP entry to ADGroup', () => {
      const entry: Entry = {
        dn: 'cn=Admins,ou=Groups,dc=example,dc=com',
        sAMAccountName: 'Admins',
        displayName: 'Domain Admins',
        groupType: '-2147483646',
      };

      const result = mapToADGroup(entry);

      expect(result.dn).toBe('cn=Admins,ou=Groups,dc=example,dc=com');
      expect(result.sAMAccountName).toBe('Admins');
      expect(result.displayName).toBe('Domain Admins');
      expect(result.groupType).toBe(-2147483646);
    });

    it('should map member array', () => {
      const entry: Entry = {
        dn: 'cn=Group,ou=Groups,dc=example,dc=com',
        sAMAccountName: 'Group',
        member: [
          'cn=User1,ou=Users,dc=example,dc=com',
          'cn=User2,ou=Users,dc=example,dc=com',
        ],
      };

      const result = mapToADGroup(entry);

      expect(result.member).toHaveLength(2);
      expect(result.member).toContain('cn=User1,ou=Users,dc=example,dc=com');
    });

    it('should map memberOf array', () => {
      const entry: Entry = {
        dn: 'cn=Group,ou=Groups,dc=example,dc=com',
        sAMAccountName: 'Group',
        memberOf: ['cn=ParentGroup,ou=Groups,dc=example,dc=com'],
      };

      const result = mapToADGroup(entry);

      expect(result.memberOf).toHaveLength(1);
      expect(result.memberOf).toContain('cn=ParentGroup,ou=Groups,dc=example,dc=com');
    });

    it('should handle missing optional fields', () => {
      const entry: Entry = {
        dn: 'cn=Minimal,ou=Groups,dc=example,dc=com',
        sAMAccountName: 'Minimal',
      };

      const result = mapToADGroup(entry);

      expect(result.sAMAccountName).toBe('Minimal');
      expect(result.displayName).toBeUndefined();
      expect(result.groupType).toBeUndefined();
      expect(result.member).toBeUndefined();
    });

    it('should include extra attributes', () => {
      const entry: Entry = {
        dn: 'cn=Group,ou=Groups,dc=example,dc=com',
        sAMAccountName: 'Group',
        description: 'Test group',
        customAttr: 'value',
      };

      const result = mapToADGroup(entry);

      expect(result['description']).toBe('Test group');
      expect(result['customAttr']).toBe('value');
    });
  });

  describe('mapToADComputer', () => {
    it('should map basic LDAP entry to ADComputer', () => {
      const entry: Entry = {
        dn: 'cn=WORKSTATION1,ou=Computers,dc=example,dc=com',
        sAMAccountName: 'WORKSTATION1$',
        dNSHostName: 'workstation1.example.com',
        operatingSystem: 'Windows 10 Enterprise',
        operatingSystemVersion: '10.0 (19045)',
        userAccountControl: '4096', // Workstation trust account
      };

      const result = mapToADComputer(entry);

      expect(result.dn).toBe('cn=WORKSTATION1,ou=Computers,dc=example,dc=com');
      expect(result.sAMAccountName).toBe('WORKSTATION1$');
      expect(result.dNSHostName).toBe('workstation1.example.com');
      expect(result.operatingSystem).toBe('Windows 10 Enterprise');
      expect(result.operatingSystemVersion).toBe('10.0 (19045)');
      expect(result.enabled).toBe(true);
    });

    it('should map disabled computer', () => {
      const entry: Entry = {
        dn: 'cn=OLD-PC,ou=Computers,dc=example,dc=com',
        sAMAccountName: 'OLD-PC$',
        userAccountControl: '4098', // Disabled workstation (4096 + 2)
      };

      const result = mapToADComputer(entry);

      expect(result.enabled).toBe(false);
    });

    it('should convert lastLogon FILETIME', () => {
      const entry: Entry = {
        dn: 'cn=PC1,ou=Computers,dc=example,dc=com',
        sAMAccountName: 'PC1$',
        lastLogon: '132850000000000000',
      };

      const result = mapToADComputer(entry);

      expect(result.lastLogon).toBeInstanceOf(Date);
    });

    it('should handle missing optional fields', () => {
      const entry: Entry = {
        dn: 'cn=Minimal,ou=Computers,dc=example,dc=com',
        sAMAccountName: 'Minimal$',
      };

      const result = mapToADComputer(entry);

      expect(result.dNSHostName).toBeUndefined();
      expect(result.operatingSystem).toBeUndefined();
      expect(result.operatingSystemVersion).toBeUndefined();
      expect(result.lastLogon).toBeUndefined();
    });
  });

  describe('mapToADOU', () => {
    it('should map basic LDAP entry to ADOU', () => {
      const entry: Entry = {
        dn: 'ou=Users,dc=example,dc=com',
        name: 'Users',
        description: 'User accounts',
      };

      const result = mapToADOU(entry);

      expect(result.dn).toBe('ou=Users,dc=example,dc=com');
      expect(result.name).toBe('Users');
      expect(result.description).toBe('User accounts');
    });

    it('should use ou attribute if name is missing', () => {
      const entry: Entry = {
        dn: 'ou=Users,dc=example,dc=com',
        ou: 'Users',
      };

      const result = mapToADOU(entry);

      expect(result.name).toBe('Users');
    });

    it('should handle missing description', () => {
      const entry: Entry = {
        dn: 'ou=Users,dc=example,dc=com',
        name: 'Users',
      };

      const result = mapToADOU(entry);

      expect(result.name).toBe('Users');
      expect(result.description).toBeUndefined();
    });

    it('should include extra attributes', () => {
      const entry: Entry = {
        dn: 'ou=Users,dc=example,dc=com',
        name: 'Users',
        managedBy: 'cn=Admin,ou=Users,dc=example,dc=com',
      };

      const result = mapToADOU(entry);

      expect(result['managedBy']).toBe('cn=Admin,ou=Users,dc=example,dc=com');
    });
  });

  describe('mapToGeneric', () => {
    it('should map all attributes to generic object', () => {
      const entry: Entry = {
        dn: 'cn=Object,dc=example,dc=com',
        attribute1: 'value1',
        attribute2: 'value2',
        numericAttr: '123',
      };

      const result = mapToGeneric(entry);

      expect(result['dn']).toBe('cn=Object,dc=example,dc=com');
      expect(result['attribute1']).toBe('value1');
      expect(result['attribute2']).toBe('value2');
      expect(result['numericAttr']).toBe(123); // Converted to number
    });

    it('should convert numeric strings to numbers', () => {
      const entry: Entry = {
        dn: 'cn=Object,dc=example,dc=com',
        count: '42',
        id: '1000',
      };

      const result = mapToGeneric(entry);

      expect(result['count']).toBe(42);
      expect(result['id']).toBe(1000);
    });

    it('should convert Buffer values to strings', () => {
      const entry: Entry = {
        dn: 'cn=Object,dc=example,dc=com',
        binaryAttr: Buffer.from('test'),
      };

      const result = mapToGeneric(entry);

      expect(result['binaryAttr']).toBe('test');
    });

    it('should handle array values', () => {
      const entry: Entry = {
        dn: 'cn=Object,dc=example,dc=com',
        multiValue: ['value1', 'value2', 'value3'],
      };

      const result = mapToGeneric(entry);

      expect(Array.isArray(result['multiValue'])).toBe(true);
      expect(result['multiValue']).toHaveLength(3);
    });

    it('should convert Buffer arrays to string arrays', () => {
      const entry: Entry = {
        dn: 'cn=Object,dc=example,dc=com',
        binaryArray: [Buffer.from('test1'), Buffer.from('test2')],
      };

      const result = mapToGeneric(entry);

      expect(result['binaryArray']).toEqual(['test1', 'test2']);
    });
  });
});
