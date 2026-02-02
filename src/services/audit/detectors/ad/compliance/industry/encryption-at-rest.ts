/**
 * ENCRYPTION_AT_REST_DISABLED - BitLocker not deployed on DCs
 * Frameworks: PCI-DSS 3.4, HIPAA 164.312(a)(2)(iv), ISO27001 A.10.1.1
 * Checks if domain controllers have encryption indicators
 */

import { ADComputer } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';
import { ldapAttrToString } from '../../../../../../utils/entity-converter';

export function detectEncryptionAtRestDisabled(
  computers: ADComputer[],
  _includeDetails: boolean
): Finding {
  // Find domain controllers
  const domainControllers = computers.filter((c) => {
    const uac = c.userAccountControl || 0;
    return (uac & 0x2000) !== 0; // SERVER_TRUST_ACCOUNT
  });

  // Check for BitLocker recovery information
  // In AD, BitLocker keys are stored as msFVE-RecoveryInformation objects linked to computer
  const dcsWithoutBitLocker = domainControllers.filter((dc) => {
    // Check for msFVE attributes (BitLocker)
    const hasBitLocker = dc['msFVE-RecoveryPassword'] || dc['msFVE-KeyPackage'];
    return !hasBitLocker;
  });

  // Also check all servers for encryption
  const servers = computers.filter((c) => {
    const os = ldapAttrToString(c.operatingSystem).toLowerCase();
    return os.includes('server') && !domainControllers.includes(c);
  });

  const serversWithoutBitLocker = servers.filter((s) => {
    const hasBitLocker = s['msFVE-RecoveryPassword'] || s['msFVE-KeyPackage'];
    return !hasBitLocker;
  });

  const issues: string[] = [];
  if (dcsWithoutBitLocker.length > 0) {
    issues.push(`${dcsWithoutBitLocker.length}/${domainControllers.length} Domain Controllers without BitLocker`);
  }
  if (serversWithoutBitLocker.length > 0 && serversWithoutBitLocker.length === servers.length) {
    issues.push(`No servers have BitLocker recovery stored in AD`);
  }

  return {
    type: 'ENCRYPTION_AT_REST_DISABLED',
    severity: 'high',
    category: 'compliance',
    title: 'Encryption at Rest Not Deployed',
    description:
      'BitLocker encryption not detected on domain controllers or servers. Required by PCI-DSS 3.4, HIPAA 164.312(a)(2)(iv), ISO27001 A.10.1.1.',
    count: dcsWithoutBitLocker.length,
    details: issues.length > 0 ? {
      violations: issues,
      domainControllers: domainControllers.length,
      dcsWithBitLocker: domainControllers.length - dcsWithoutBitLocker.length,
      frameworks: ['PCI-DSS', 'HIPAA', 'ISO27001'],
      controls: ['3.4', '164.312(a)(2)(iv)', 'A.10.1.1'],
      recommendation: 'Deploy BitLocker on all domain controllers and servers with AD key backup',
    } : undefined,
  };
}
