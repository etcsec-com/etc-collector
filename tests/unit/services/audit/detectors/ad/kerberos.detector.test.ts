/**
 * Unit Tests for Kerberos Security Vulnerability Detector
 * Story 1.7: AD Vulnerability Detection Engine
 *
 * Tests all Kerberos-related vulnerability detectors:
 * - ASREP_ROASTING_RISK
 * - UNCONSTRAINED_DELEGATION
 * - KERBEROASTING_RISK
 * - CONSTRAINED_DELEGATION
 * - WEAK_ENCRYPTION_DES
 * - WEAK_ENCRYPTION_FLAG
 * - GOLDEN_TICKET_RISK
 */

import {
  detectAsrepRoastingRisk,
  detectUnconstrainedDelegation,
  detectKerberoastingRisk,
  detectConstrainedDelegation,
  detectWeakEncryptionDES,
  detectWeakEncryptionFlag,
  detectGoldenTicketRisk,
} from '../../../../../../src/services/audit/detectors/ad/kerberos.detector';
import { ADUser } from '../../../../../../src/types/ad.types';

describe('Kerberos Security Detectors', () => {
  const createUser = (overrides: Partial<ADUser> = {}): ADUser => ({
    dn: 'CN=TestUser,DC=example,DC=com',
    sAMAccountName: 'testuser',
    enabled: true,
    userAccountControl: 0,
    ...overrides,
  });

  describe('detectAsrepRoastingRisk', () => {
    it('should detect users without Kerberos pre-auth (0x400000)', () => {
      const users: ADUser[] = [
        createUser({ sAMAccountName: 'user1', userAccountControl: 0x400000 }),
        createUser({ sAMAccountName: 'user2', userAccountControl: 0x00 }),
        createUser({ sAMAccountName: 'user3', userAccountControl: 0x400200 }),
      ];

      const result = detectAsrepRoastingRisk(users, false);

      expect(result.type).toBe('ASREP_ROASTING_RISK');
      expect(result.severity).toBe('critical');
      expect(result.category).toBe('kerberos');
      expect(result.count).toBe(2);
    });

    it('should include affected entities when includeDetails=true', () => {
      const users: ADUser[] = [
        createUser({ sAMAccountName: 'vulnerable', userAccountControl: 0x400000 }),
      ];

      const result = detectAsrepRoastingRisk(users, true);

      expect(result.affectedEntities).toBeDefined();
      expect(result.affectedEntities).toHaveLength(1);
    });
  });

  describe('detectUnconstrainedDelegation', () => {
    it('should detect users with unconstrained delegation (0x80000)', () => {
      const users: ADUser[] = [
        createUser({ sAMAccountName: 'user1', userAccountControl: 0x80000 }),
        createUser({ sAMAccountName: 'user2', userAccountControl: 0x00 }),
      ];

      const result = detectUnconstrainedDelegation(users, false);

      expect(result.type).toBe('UNCONSTRAINED_DELEGATION');
      expect(result.severity).toBe('critical');
      expect(result.count).toBe(1);
    });
  });

  describe('detectKerberoastingRisk', () => {
    it('should detect users with SPNs', () => {
      const users: ADUser[] = [
        createUser({
          sAMAccountName: 'serviceacct',
          servicePrincipalName: ['HTTP/server.example.com', 'MSSQL/db.example.com'],
        } as any),
        createUser({ sAMAccountName: 'normaluser' }),
      ];

      const result = detectKerberoastingRisk(users, false);

      expect(result.type).toBe('KERBEROASTING_RISK');
      expect(result.severity).toBe('high');
      expect(result.count).toBe(1);
    });

    it('should handle empty SPN arrays', () => {
      const users: ADUser[] = [
        createUser({ servicePrincipalName: [] } as any),
        createUser({ servicePrincipalName: undefined } as any),
      ];

      const result = detectKerberoastingRisk(users, false);
      expect(result.count).toBe(0);
    });
  });

  describe('detectConstrainedDelegation', () => {
    it('should detect users with constrained delegation (0x1000000)', () => {
      const users: ADUser[] = [
        createUser({ sAMAccountName: 'delegateuser', userAccountControl: 0x1000000 }),
        createUser({ sAMAccountName: 'normaluser', userAccountControl: 0x00 }),
      ];

      const result = detectConstrainedDelegation(users, false);

      expect(result.type).toBe('CONSTRAINED_DELEGATION');
      expect(result.severity).toBe('high');
      expect(result.count).toBe(1);
    });
  });

  describe('detectWeakEncryptionDES', () => {
    it('should detect DES encryption enabled (0x200000)', () => {
      const users: ADUser[] = [
        createUser({ sAMAccountName: 'user1', userAccountControl: 0x200000 }),
        createUser({ sAMAccountName: 'user2', userAccountControl: 0x00 }),
        createUser({ sAMAccountName: 'user3', userAccountControl: 0x200200 }),
      ];

      const result = detectWeakEncryptionDES(users, false);

      expect(result.type).toBe('WEAK_ENCRYPTION_DES');
      expect(result.severity).toBe('high');
      expect(result.count).toBe(2);
    });
  });

  describe('detectWeakEncryptionFlag', () => {
    it('should detect USE_DES_KEY_ONLY flag (0x200000)', () => {
      const users: ADUser[] = [
        createUser({ sAMAccountName: 'user1', userAccountControl: 0x200000 }),
        createUser({ sAMAccountName: 'user2', userAccountControl: 0x00 }),
      ];

      const result = detectWeakEncryptionFlag(users, false);

      expect(result.type).toBe('WEAK_ENCRYPTION_FLAG');
      expect(result.severity).toBe('medium');
      expect(result.count).toBe(1);
    });
  });

  describe('detectGoldenTicketRisk', () => {
    it('should detect krbtgt with old password (>180 days)', () => {
      const now = new Date();
      const old = new Date(now.getTime() - 200 * 24 * 60 * 60 * 1000); // 200 days
      const recent = new Date(now.getTime() - 100 * 24 * 60 * 60 * 1000);

      const users: ADUser[] = [
        createUser({
          sAMAccountName: 'krbtgt',
          passwordLastSet: old,
        }),
        createUser({
          sAMAccountName: 'krbtgt',
          passwordLastSet: recent,
        }),
        createUser({
          sAMAccountName: 'normaluser',
          passwordLastSet: old,
        }),
      ];

      const result = detectGoldenTicketRisk(users, false);

      expect(result.type).toBe('GOLDEN_TICKET_RISK');
      expect(result.severity).toBe('critical');
      expect(result.count).toBe(1);
    });

    it('should handle missing passwordLastSet', () => {
      const users: ADUser[] = [
        createUser({
          sAMAccountName: 'krbtgt',
          passwordLastSet: undefined,
        }),
      ];

      const result = detectGoldenTicketRisk(users, false);
      expect(result.count).toBe(0);
    });
  });

  describe('Integration Tests', () => {
    it('should detect multiple Kerberos vulnerabilities on same user', () => {
      const users: ADUser[] = [
        createUser({
          sAMAccountName: 'baduser',
          userAccountControl: 0x680000, // Unconstrained + AS-REP Roasting + DES
          servicePrincipalName: ['HTTP/server'],
          'msDS-AllowedToDelegateTo': ['CIFS/file'],
        } as any),
      ];

      const asrep = detectAsrepRoastingRisk(users, false);
      const unconstrained = detectUnconstrainedDelegation(users, false);
      const kerberoast = detectKerberoastingRisk(users, false);
      const constrained = detectConstrainedDelegation(users, false);
      const weakDes = detectWeakEncryptionFlag(users, false);

      const totalVulns = asrep.count + unconstrained.count + kerberoast.count +
                         constrained.count + weakDes.count;
      expect(totalVulns).toBeGreaterThan(0);
    });
  });
});
