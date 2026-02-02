/**
 * Windows Security Descriptor & ACL Parser
 *
 * Parses binary ntSecurityDescriptor attribute from AD
 * to extract Access Control Entries (ACEs) for security analysis.
 *
 * References:
 * - MS-DTYP: Security Descriptor
 * - https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/
 */

import { AclEntry } from '../../types/ad.types';

/**
 * ACE Types
 */
enum AceType {
  ACCESS_ALLOWED = 0x00,
  ACCESS_DENIED = 0x01,
  SYSTEM_AUDIT = 0x02,
  ACCESS_ALLOWED_OBJECT = 0x05,
  ACCESS_DENIED_OBJECT = 0x06,
  SYSTEM_AUDIT_OBJECT = 0x07,
}

/**
 * ACE Flags for Object ACEs
 */
enum ObjectAceFlags {
  NONE = 0x00,
  ACE_OBJECT_TYPE_PRESENT = 0x01,
  ACE_INHERITED_OBJECT_TYPE_PRESENT = 0x02,
}

/**
 * Parse ntSecurityDescriptor binary data into ACL entries
 *
 * @param securityDescriptor Binary security descriptor buffer
 * @param objectDn DN of the object (for reference)
 * @returns Array of ACL entries
 */
export function parseSecurityDescriptor(securityDescriptor: Buffer, objectDn: string): AclEntry[] {
  if (!securityDescriptor || securityDescriptor.length < 20) {
    return [];
  }

  try {
    parseStats.total++;
    const aclEntries: AclEntry[] = [];

    // Parse Security Descriptor header
    // const revision = securityDescriptor.readUInt8(0); // Not used
    const control = securityDescriptor.readUInt16LE(2);

    // Check if DACL is present (SE_DACL_PRESENT = 0x0004)
    const daclPresent = (control & 0x0004) !== 0;
    if (!daclPresent) {
      return [];
    }

    // Get DACL offset
    const daclOffset = securityDescriptor.readUInt32LE(16);
    if (daclOffset === 0 || daclOffset >= securityDescriptor.length) {
      return [];
    }

    // Parse DACL
    const dacl = securityDescriptor.slice(daclOffset);
    // const aclRevision = dacl.readUInt8(0); // Not used
    const aclSize = dacl.readUInt16LE(2);
    const aceCount = dacl.readUInt16LE(4);

    // Parse each ACE
    let aceOffset = 8; // ACL header is 8 bytes
    for (let i = 0; i < aceCount; i++) {
      if (aceOffset >= aclSize) break;

      const ace = parseAce(dacl, aceOffset, objectDn);
      if (ace) {
        aclEntries.push(ace);
      }

      // Move to next ACE
      const aceSize = dacl.readUInt16LE(aceOffset + 2);
      aceOffset += aceSize;
    }

    if (aclEntries.length > 0) {
      parseStats.withACEs++;
    }
    return aclEntries;
  } catch (error) {
    // Silently fail on parse errors - many objects may have unusual security descriptors
    return [];
  }
}

// Track parsing stats (for debugging)
let parseStats = { total: 0, withACEs: 0 };
export function getParseStats() {
  return parseStats;
}
export function resetParseStats() {
  parseStats = { total: 0, withACEs: 0 };
}

/**
 * Parse a single ACE from DACL
 */
function parseAce(dacl: Buffer, offset: number, objectDn: string): AclEntry | null {
  try {
    const aceType = dacl.readUInt8(offset);
    // const aceFlags = dacl.readUInt8(offset + 1); // Not used
    // const aceSize = dacl.readUInt16LE(offset + 2); // Read in caller loop
    const accessMask = dacl.readUInt32LE(offset + 4);

    // We only care about ACCESS_ALLOWED and ACCESS_ALLOWED_OBJECT ACEs
    if (aceType !== AceType.ACCESS_ALLOWED && aceType !== AceType.ACCESS_ALLOWED_OBJECT) {
      return null;
    }

    let sidOffset = 8; // Standard ACE: type(1) + flags(1) + size(2) + mask(4)
    let objectType: string | undefined;

    // Handle Object ACEs (have optional GUIDs before SID)
    if (aceType === AceType.ACCESS_ALLOWED_OBJECT) {
      const objectFlags = dacl.readUInt32LE(offset + 8);
      sidOffset = 12; // Object ACE: + flags(4)

      // If ACE_OBJECT_TYPE_PRESENT flag is set, there's a GUID
      if ((objectFlags & ObjectAceFlags.ACE_OBJECT_TYPE_PRESENT) !== 0) {
        objectType = parseGuid(dacl, offset + sidOffset);
        sidOffset += 16; // GUID is 16 bytes
      }

      // If ACE_INHERITED_OBJECT_TYPE_PRESENT flag is set, skip inherited GUID
      if ((objectFlags & ObjectAceFlags.ACE_INHERITED_OBJECT_TYPE_PRESENT) !== 0) {
        sidOffset += 16;
      }
    }

    // Parse SID
    const sid = parseSid(dacl, offset + sidOffset);

    return {
      objectDn,
      trustee: sid,
      accessMask,
      aceType: aceTypeToString(aceType),
      objectType,
    };
  } catch (error) {
    return null;
  }
}

/**
 * Parse Windows SID from binary format
 */
function parseSid(buffer: Buffer, offset: number): string {
  try {
    const revision = buffer.readUInt8(offset);
    const subAuthorityCount = buffer.readUInt8(offset + 1);

    // Read identifier authority (6 bytes, big-endian)
    const identifierAuthority =
      buffer.readUInt8(offset + 2) * 0x0000010000000000 +
      buffer.readUInt8(offset + 3) * 0x0000000100000000 +
      buffer.readUInt8(offset + 4) * 0x0000000001000000 +
      buffer.readUInt8(offset + 5) * 0x0000000000010000 +
      buffer.readUInt8(offset + 6) * 0x0000000000000100 +
      buffer.readUInt8(offset + 7);

    // Build SID string
    let sid = `S-${revision}-${identifierAuthority}`;

    // Read sub-authorities (4 bytes each, little-endian)
    let subAuthOffset = offset + 8;
    for (let i = 0; i < subAuthorityCount; i++) {
      const subAuth = buffer.readUInt32LE(subAuthOffset);
      sid += `-${subAuth}`;
      subAuthOffset += 4;
    }

    return sid;
  } catch (error) {
    return 'S-1-0-0'; // Return null SID on error
  }
}

/**
 * Parse GUID from binary format to string
 */
function parseGuid(buffer: Buffer, offset: number): string {
  try {
    const data1 = buffer.readUInt32LE(offset).toString(16).padStart(8, '0');
    const data2 = buffer.readUInt16LE(offset + 4).toString(16).padStart(4, '0');
    const data3 = buffer.readUInt16LE(offset + 6).toString(16).padStart(4, '0');
    const data4 = buffer.readUInt8(offset + 8).toString(16).padStart(2, '0');
    const data5 = buffer.readUInt8(offset + 9).toString(16).padStart(2, '0');
    const data6 = buffer
      .slice(offset + 10, offset + 16)
      .toString('hex');

    return `${data1}-${data2}-${data3}-${data4}${data5}-${data6}`;
  } catch (error) {
    return '00000000-0000-0000-0000-000000000000';
  }
}

/**
 * Convert ACE type enum to string
 */
function aceTypeToString(aceType: number): string {
  switch (aceType) {
    case AceType.ACCESS_ALLOWED:
      return 'ACCESS_ALLOWED';
    case AceType.ACCESS_DENIED:
      return 'ACCESS_DENIED';
    case AceType.SYSTEM_AUDIT:
      return 'SYSTEM_AUDIT';
    case AceType.ACCESS_ALLOWED_OBJECT:
      return 'ACCESS_ALLOWED_OBJECT';
    case AceType.ACCESS_DENIED_OBJECT:
      return 'ACCESS_DENIED_OBJECT';
    case AceType.SYSTEM_AUDIT_OBJECT:
      return 'SYSTEM_AUDIT_OBJECT';
    default:
      return `UNKNOWN_${aceType}`;
  }
}
