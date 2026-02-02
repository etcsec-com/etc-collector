/**
 * Unit Tests for Computers Security Vulnerability Detector
 * Story 1.7: AD Vulnerability Detection Engine
 *
 * Tests all computer-related vulnerability detectors (17 types):
 * - COMPUTER_CONSTRAINED_DELEGATION
 * - COMPUTER_RBCD
 * - COMPUTER_IN_ADMIN_GROUP
 * - COMPUTER_DCSYNC_RIGHTS
 * - COMPUTER_UNCONSTRAINED_DELEGATION
 * - COMPUTER_STALE_INACTIVE
 * - COMPUTER_PASSWORD_OLD
 * - COMPUTER_WITH_SPNS
 * - COMPUTER_NO_LAPS
 * - COMPUTER_ACL_ABUSE
 * - COMPUTER_DISABLED_NOT_DELETED
 * - COMPUTER_WRONG_OU
 * - COMPUTER_WEAK_ENCRYPTION
 * - COMPUTER_DESCRIPTION_SENSITIVE
 * - COMPUTER_PRE_WINDOWS_2000
 * - COMPUTER_ADMIN_COUNT
 * - COMPUTER_SMB_SIGNING_DISABLED
 */

import {
  detectComputerConstrainedDelegation,
  detectComputerRbcd,
  detectComputerInAdminGroup,
  detectComputerDcsyncRights,
  detectComputerUnconstrainedDelegation,
  detectComputerStaleInactive,
  detectComputerPasswordOld,
  detectComputerWithSpns,
  detectComputerNoLaps,
  detectComputerAclAbuse,
  detectComputerDisabledNotDeleted,
  detectComputerWrongOu,
  detectComputerWeakEncryption,
  detectComputerDescriptionSensitive,
  detectComputerPreWindows2000,
  detectComputerAdminCount,
  detectComputerSmbSigningDisabled,
} from '../../../../../../src/services/audit/detectors/ad/computers.detector';
import { ADComputer } from '../../../../../../src/types/ad.types';

describe('Computers Security Detectors', () => {
  const createComputer = (overrides: Partial<ADComputer> = {}): ADComputer => ({
    dn: 'CN=TESTPC,OU=Computers,DC=example,DC=com',
    sAMAccountName: 'TESTPC$',
    enabled: true,
    ...overrides,
  });

  describe('detectComputerConstrainedDelegation', () => {
    it('should detect computers with constrained delegation', () => {
      const computers: ADComputer[] = [
        createComputer({
          sAMAccountName: 'SERVER1$',
          'msDS-AllowedToDelegateTo': ['CIFS/fileserver.example.com'],
        } as any),
        createComputer({ sAMAccountName: 'WORKSTATION1$' }),
      ];

      const result = detectComputerConstrainedDelegation(computers, false);

      expect(result.type).toBe('COMPUTER_CONSTRAINED_DELEGATION');
      expect(result.severity).toBe('critical');
      expect(result.category).toBe('computers');
      expect(result.count).toBe(1);
    });

    it('should handle empty delegation arrays', () => {
      const computers: ADComputer[] = [
        createComputer({ 'msDS-AllowedToDelegateTo': [] } as any),
      ];

      const result = detectComputerConstrainedDelegation(computers, false);
      expect(result.count).toBe(0);
    });
  });

  describe('detectComputerRbcd', () => {
    it('should detect computers with RBCD configured', () => {
      const computers: ADComputer[] = [
        createComputer({
          sAMAccountName: 'WEB-SERVER$',
          'msDS-AllowedToActOnBehalfOfOtherIdentity': 'some-rbcd-data',
        } as any),
        createComputer({ sAMAccountName: 'NORMAL-PC$' }),
      ];

      const result = detectComputerRbcd(computers, false);

      expect(result.type).toBe('COMPUTER_RBCD');
      expect(result.severity).toBe('critical');
      expect(result.count).toBe(1);
    });
  });

  describe('detectComputerInAdminGroup', () => {
    it('should detect computers in admin groups', () => {
      const computers: ADComputer[] = [
        createComputer({
          sAMAccountName: 'ADMIN-SERVER$',
          memberOf: ['CN=Domain Admins,DC=example,DC=com'],
        } as any),
        createComputer({
          sAMAccountName: 'REGULAR-PC$',
          memberOf: ['CN=Computers,DC=example,DC=com'],
        } as any),
      ];

      const result = detectComputerInAdminGroup(computers, false);

      expect(result.type).toBe('COMPUTER_IN_ADMIN_GROUP');
      expect(result.severity).toBe('critical');
      expect(result.count).toBe(1);
    });
  });

  describe('detectComputerDcsyncRights', () => {
    it('should detect computers with DCSync rights', () => {
      const computers: ADComputer[] = [
        createComputer({
          sAMAccountName: 'EVIL-SERVER$',
          replicationRights: true,
        } as any),
        createComputer({ sAMAccountName: 'NORMAL-PC$' }),
      ];

      const result = detectComputerDcsyncRights(computers, false);

      expect(result.type).toBe('COMPUTER_DCSYNC_RIGHTS');
      expect(result.severity).toBe('critical');
      expect(result.count).toBe(1);
    });
  });

  describe('detectComputerUnconstrainedDelegation', () => {
    it('should detect unconstrained delegation (0x80000)', () => {
      const computers: ADComputer[] = [
        createComputer({
          sAMAccountName: 'DC01$',
          userAccountControl: 0x80000,
        } as any),
        createComputer({
          sAMAccountName: 'WS01$',
          userAccountControl: 0x1000,
        } as any),
      ];

      const result = detectComputerUnconstrainedDelegation(computers, false);

      expect(result.type).toBe('COMPUTER_UNCONSTRAINED_DELEGATION');
      expect(result.severity).toBe('critical');
      expect(result.count).toBe(1);
    });
  });

  describe('detectComputerStaleInactive', () => {
    it('should detect computers inactive for 90+ days', () => {
      const now = new Date();
      const old = new Date(now.getTime() - 100 * 24 * 60 * 60 * 1000); // 100 days
      const recent = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000); // 30 days

      const computers: ADComputer[] = [
        createComputer({ sAMAccountName: 'STALE-PC$', lastLogon: old }),
        createComputer({ sAMAccountName: 'ACTIVE-PC$', lastLogon: recent }),
      ];

      const result = detectComputerStaleInactive(computers, false);

      expect(result.type).toBe('COMPUTER_STALE_INACTIVE');
      expect(result.severity).toBe('high');
      expect(result.count).toBe(1);
    });
  });

  describe('detectComputerPasswordOld', () => {
    it('should detect computers with old passwords (90+ days)', () => {
      const now = new Date();
      const old = new Date(now.getTime() - 100 * 24 * 60 * 60 * 1000);
      const recent = new Date(now.getTime() - 50 * 24 * 60 * 60 * 1000);

      const computers: ADComputer[] = [
        createComputer({ sAMAccountName: 'OLD-PC$', pwdLastSet: old } as any),
        createComputer({ sAMAccountName: 'RECENT-PC$', pwdLastSet: recent } as any),
      ];

      const result = detectComputerPasswordOld(computers, false);

      expect(result.type).toBe('COMPUTER_PASSWORD_OLD');
      expect(result.severity).toBe('high');
      expect(result.count).toBe(1);
    });
  });

  describe('detectComputerWithSpns', () => {
    it('should detect computers with SPNs', () => {
      const computers: ADComputer[] = [
        createComputer({
          sAMAccountName: 'SQL-SERVER$',
          servicePrincipalName: ['MSSQL/sqlserver.example.com'],
        } as any),
        createComputer({ sAMAccountName: 'WORKSTATION$' }),
      ];

      const result = detectComputerWithSpns(computers, false);

      expect(result.type).toBe('COMPUTER_WITH_SPNS');
      expect(result.severity).toBe('high');
      expect(result.count).toBe(1);
    });
  });

  describe('detectComputerNoLaps', () => {
    it('should detect computers without LAPS', () => {
      const computers: ADComputer[] = [
        createComputer({
          sAMAccountName: 'WITH-LAPS$',
          'ms-Mcs-AdmPwd': 'encrypted-password',
        } as any),
        createComputer({
          sAMAccountName: 'NEW-LAPS$',
          'msLAPS-Password': 'encrypted',
        } as any),
        createComputer({ sAMAccountName: 'NO-LAPS$' }),
      ];

      const result = detectComputerNoLaps(computers, false);

      expect(result.type).toBe('COMPUTER_NO_LAPS');
      expect(result.severity).toBe('high');
      expect(result.count).toBe(1);
    });
  });

  describe('detectComputerAclAbuse', () => {
    it('should detect computers with dangerous ACLs', () => {
      const computers: ADComputer[] = [
        createComputer({
          sAMAccountName: 'VULNERABLE$',
          dangerousAcl: true,
        } as any),
        createComputer({ sAMAccountName: 'SAFE$' }),
      ];

      const result = detectComputerAclAbuse(computers, false);

      expect(result.type).toBe('COMPUTER_ACL_ABUSE');
      expect(result.severity).toBe('high');
      expect(result.count).toBe(1);
    });
  });

  describe('detectComputerDisabledNotDeleted', () => {
    it('should detect disabled computers not deleted (30+ days)', () => {
      const now = new Date();
      const old = new Date(now.getTime() - 40 * 24 * 60 * 60 * 1000); // 40 days
      const recent = new Date(now.getTime() - 10 * 24 * 60 * 60 * 1000); // 10 days

      const computers: ADComputer[] = [
        createComputer({
          sAMAccountName: 'OLD-DISABLED$',
          enabled: false,
          whenChanged: old,
        } as any),
        createComputer({
          sAMAccountName: 'RECENT-DISABLED$',
          enabled: false,
          whenChanged: recent,
        } as any),
        createComputer({ sAMAccountName: 'ENABLED$', enabled: true }),
      ];

      const result = detectComputerDisabledNotDeleted(computers, false);

      expect(result.type).toBe('COMPUTER_DISABLED_NOT_DELETED');
      expect(result.severity).toBe('medium');
      expect(result.count).toBe(1);
    });
  });

  describe('detectComputerWrongOu', () => {
    it('should detect computers in unexpected OUs', () => {
      const computers: ADComputer[] = [
        createComputer({
          dn: 'CN=PC1,OU=Computers,DC=example,DC=com', // Correct
        }),
        createComputer({
          dn: 'CN=PC2,OU=Workstations,DC=example,DC=com', // Correct
        }),
        createComputer({
          dn: 'CN=PC3,OU=Users,DC=example,DC=com', // Wrong!
        }),
      ];

      const result = detectComputerWrongOu(computers, false);

      expect(result.type).toBe('COMPUTER_WRONG_OU');
      expect(result.severity).toBe('medium');
      expect(result.count).toBe(1);
    });
  });

  describe('detectComputerWeakEncryption', () => {
    it('should detect computers with weak encryption only', () => {
      const computers: ADComputer[] = [
        createComputer({
          sAMAccountName: 'WEAK$',
          'msDS-SupportedEncryptionTypes': 0x07, // DES/RC4 only
        } as any),
        createComputer({
          sAMAccountName: 'STRONG$',
          'msDS-SupportedEncryptionTypes': 0x18, // AES
        } as any),
      ];

      const result = detectComputerWeakEncryption(computers, false);

      expect(result.type).toBe('COMPUTER_WEAK_ENCRYPTION');
      expect(result.severity).toBe('medium');
      expect(result.count).toBe(1);
    });
  });

  describe('detectComputerDescriptionSensitive', () => {
    it('should detect sensitive data in descriptions', () => {
      const computers: ADComputer[] = [
        createComputer({
          description: 'Server password: MySecret123',
        } as any),
        createComputer({
          description: 'IP: 192.168.1.100',
        } as any),
        createComputer({
          description: 'Admin server for IT',
        } as any),
        createComputer({
          description: 'Normal workstation',
        } as any),
      ];

      const result = detectComputerDescriptionSensitive(computers, false);

      expect(result.type).toBe('COMPUTER_DESCRIPTION_SENSITIVE');
      expect(result.severity).toBe('medium');
      expect(result.count).toBe(3); // password, IP, admin
    });
  });

  describe('detectComputerPreWindows2000', () => {
    it('should detect pre-Windows 2000 computers', () => {
      const computers: ADComputer[] = [
        createComputer({
          operatingSystem: 'Windows NT 4.0',
        }),
        createComputer({
          operatingSystem: 'Windows 2000 Server',
        }),
        createComputer({
          operatingSystem: 'Windows Server 2019',
        }),
      ];

      const result = detectComputerPreWindows2000(computers, false);

      expect(result.type).toBe('COMPUTER_PRE_WINDOWS_2000');
      expect(result.severity).toBe('medium');
      expect(result.count).toBe(2);
    });
  });

  describe('detectComputerAdminCount', () => {
    it('should detect computers with adminCount=1', () => {
      const computers: ADComputer[] = [
        createComputer({
          sAMAccountName: 'ADMIN-PC$',
          adminCount: 1,
        } as any),
        createComputer({
          sAMAccountName: 'NORMAL-PC$',
          adminCount: 0,
        } as any),
        createComputer({ sAMAccountName: 'NO-ATTR$' }),
      ];

      const result = detectComputerAdminCount(computers, false);

      expect(result.type).toBe('COMPUTER_ADMIN_COUNT');
      expect(result.severity).toBe('low');
      expect(result.count).toBe(1);
    });
  });

  describe('detectComputerSmbSigningDisabled', () => {
    it('should detect computers with SMB signing disabled', () => {
      const computers: ADComputer[] = [
        createComputer({
          sAMAccountName: 'NOSIGN$',
          smbSigningDisabled: true,
        } as any),
        createComputer({ sAMAccountName: 'SIGNED$' }),
      ];

      const result = detectComputerSmbSigningDisabled(computers, false);

      expect(result.type).toBe('COMPUTER_SMB_SIGNING_DISABLED');
      expect(result.severity).toBe('low');
      expect(result.count).toBe(1);
    });
  });

  describe('Integration Tests', () => {
    it('should detect multiple vulnerabilities on same computer', () => {
      const computers: ADComputer[] = [
        createComputer({
          sAMAccountName: 'BAD-SERVER$',
          userAccountControl: 0x80000, // Unconstrained delegation
          memberOf: ['CN=Domain Admins,DC=example,DC=com'],
          'msDS-AllowedToDelegateTo': ['CIFS/fileserver'],
          description: 'Password: test123',
        } as any),
      ];

      const unconstrained = detectComputerUnconstrainedDelegation(computers, false);
      const adminGroup = detectComputerInAdminGroup(computers, false);
      const constrained = detectComputerConstrainedDelegation(computers, false);
      const sensitive = detectComputerDescriptionSensitive(computers, false);

      const totalVulns = unconstrained.count + adminGroup.count + constrained.count + sensitive.count;
      expect(totalVulns).toBeGreaterThan(0);
    });

    it('should handle empty computer list', () => {
      const result = detectComputerStaleInactive([], false);
      expect(result.count).toBe(0);
    });
  });
});
