/**
 * Computer No LAPS Detector
 * Check for computer without LAPS
 * Checks for both legacy LAPS (ms-Mcs-AdmPwd) and Windows LAPS (msLAPS-Password)
 *
 * Note: Password attributes may not be readable without LAPS admin rights,
 * so we also check expiration time attributes which are more accessible.
 * If LAPS schema is not extended, ALL computers are flagged.
 */

import { ADComputer } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';
import { toAffectedComputerEntities } from '../../../../../../utils/entity-converter';

export function detectComputerNoLaps(computers: ADComputer[], includeDetails: boolean): Finding {
  // Stats for debugging
  const total = computers.length;
  const disabled = computers.filter((c) => !c.enabled).length;
  const enabled = total - disabled;

  // Count DCs (SERVER_TRUST_ACCOUNT = 0x2000)
  const domainControllers = computers.filter((c) => {
    const uac = (c as any).userAccountControl;
    return uac && (uac & 0x2000) !== 0;
  }).length;

  // Check if any computer has LAPS attributes (indicates schema is extended)
  let hasLegacyLapsSchema = false;
  let hasWindowsLapsSchema = false;
  let withLegacyLaps = 0;
  let withWindowsLaps = 0;

  const affected = computers.filter((c) => {
    // Only check enabled computers (workstations and servers, not DCs)
    if (!c.enabled) return false;

    // Skip Domain Controllers (they don't use LAPS)
    const uac = (c as any).userAccountControl;
    if (uac && (uac & 0x2000) !== 0) return false; // SERVER_TRUST_ACCOUNT = DC

    const comp = c as Record<string, unknown>;

    // Check for legacy LAPS - password or expiration time
    // Note: LDAP may return [] for non-existent attributes, so check for actual values
    const legacyLaps = comp['ms-Mcs-AdmPwd'];
    const legacyLapsExpiry = comp['ms-Mcs-AdmPwdExpirationTime'];

    // Helper to check if value is a real LAPS value (not empty/null/undefined/[])
    const isValidLapsValue = (val: unknown): boolean => {
      if (val === undefined || val === null || val === '') return false;
      if (Array.isArray(val) && val.length === 0) return false;
      if (val === '0' || val === 0) return false;
      return true;
    };

    // Track if schema attributes exist with actual values
    if (isValidLapsValue(legacyLaps) || isValidLapsValue(legacyLapsExpiry)) {
      hasLegacyLapsSchema = true;
    }

    const hasLegacyLaps = isValidLapsValue(legacyLaps) || isValidLapsValue(legacyLapsExpiry);
    if (hasLegacyLaps) withLegacyLaps++;

    // Check for Windows LAPS - password or expiration time
    const windowsLaps = comp['msLAPS-Password'];
    const windowsLapsExpiry = comp['msLAPS-PasswordExpirationTime'];

    // Track if schema attributes exist with actual values
    if (isValidLapsValue(windowsLaps) || isValidLapsValue(windowsLapsExpiry)) {
      hasWindowsLapsSchema = true;
    }

    const hasWindowsLaps = isValidLapsValue(windowsLaps) || isValidLapsValue(windowsLapsExpiry);
    if (hasWindowsLaps) withWindowsLaps++;

    // No LAPS if neither legacy nor Windows LAPS is configured
    return !hasLegacyLaps && !hasWindowsLaps;
  });

  // Determine severity based on schema availability
  const schemaExtended = hasLegacyLapsSchema || hasWindowsLapsSchema;
  const eligibleComputers = enabled - domainControllers;

  return {
    type: 'COMPUTER_NO_LAPS',
    severity: !schemaExtended ? 'critical' : 'high', // Critical if schema not extended
    category: 'computers',
    title: !schemaExtended ? 'LAPS Not Deployed (Schema Not Extended)' : 'Computer No LAPS',
    description: !schemaExtended
      ? 'LAPS schema is not extended in Active Directory. ALL local admin passwords are unmanaged and likely shared across computers.'
      : 'Computer without LAPS deployed. Shared/static local admin passwords across workstations.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedComputerEntities(affected) : undefined,
    details: {
      debug: {
        total,
        enabled,
        disabled,
        domainControllers,
        eligibleComputers,
        withLegacyLaps,
        withWindowsLaps,
        withoutLaps: affected.length,
        schemaExtended,
        hasLegacyLapsSchema,
        hasWindowsLapsSchema,
      },
      recommendation: !schemaExtended
        ? 'Install LAPS (legacy or Windows LAPS) and extend the AD schema. Then deploy via GPO.'
        : 'Deploy LAPS to remaining computers via GPO.',
    },
  };
}
