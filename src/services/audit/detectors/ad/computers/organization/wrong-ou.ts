/**
 * Computer Wrong OU Detector
 * Check for computer in default Computers container (not organized into OUs)
 *
 * Computers in "CN=Computers,DC=..." are in the default container, not an OU.
 * This indicates they haven't been organized and may not receive proper GPOs.
 *
 * Note: This is different from PingCastle's "Computer_Wrong_OU" which may
 * check for different criteria. We check for computers in default container.
 */

import { ADComputer } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';
import { toAffectedComputerEntities } from '../../../../../../utils/entity-converter';

export function detectComputerWrongOu(computers: ADComputer[], includeDetails: boolean): Finding {
  const affected = computers.filter((c) => {
    // Check if computer is directly in the default Computers container
    // DN format: CN=COMPUTER$,CN=Computers,DC=domain,DC=com
    const dnLower = c.dn.toLowerCase();

    // Check if it's in CN=Computers (not OU=)
    // This catches: CN=PC01$,CN=Computers,DC=example,DC=com
    const isInDefaultContainer = dnLower.includes(',cn=computers,dc=');

    return isInDefaultContainer;
  });

  return {
    type: 'COMPUTER_WRONG_OU',
    severity: 'medium',
    category: 'computers',
    title: 'Computer in Default Container',
    description:
      'Computer in default Computers container instead of an organizational OU. ' +
      'May not receive proper Group Policy and indicates lack of organization.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedComputerEntities(affected) : undefined,
  };
}
