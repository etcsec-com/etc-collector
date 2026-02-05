// Package ldap provides LDAP client functionality
// This file implements Windows Security Descriptor & ACL parsing
//
// Parses binary ntSecurityDescriptor attribute from AD
// to extract Access Control Entries (ACEs) for security analysis.
//
// References:
// - MS-DTYP: Security Descriptor
// - https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/

package ldap

import (
	"encoding/binary"
	"fmt"

	"github.com/etcsec-com/etc-collector/pkg/types"
)

// ACE Types
const (
	aceTypeAccessAllowed       = 0x00
	aceTypeAccessDenied        = 0x01
	aceTypeSystemAudit         = 0x02
	aceTypeAccessAllowedObject = 0x05
	aceTypeAccessDeniedObject  = 0x06
	aceTypeSystemAuditObject   = 0x07
)

// ACE Object Flags
const (
	aceObjectTypePresent          = 0x01
	aceInheritedObjectTypePresent = 0x02
)

// Security Descriptor Control Flags
const (
	seDaclPresent = 0x0004
)

// ParseSecurityDescriptor parses ntSecurityDescriptor binary data into ACL entries
func ParseSecurityDescriptor(securityDescriptor []byte, objectDN string) []types.ACLEntry {
	if len(securityDescriptor) < 20 {
		return nil
	}

	defer func() {
		// Recover from any panics during parsing
		if r := recover(); r != nil {
			// Silently fail - many objects may have unusual security descriptors
		}
	}()

	// Parse Security Descriptor header
	// Byte 0: Revision
	// Byte 1: Sbz1 (padding)
	// Bytes 2-3: Control flags (LE)
	// Bytes 4-7: OffsetOwner
	// Bytes 8-11: OffsetGroup
	// Bytes 12-15: OffsetSacl
	// Bytes 16-19: OffsetDacl

	control := binary.LittleEndian.Uint16(securityDescriptor[2:4])

	// Check if DACL is present
	if (control & seDaclPresent) == 0 {
		return nil
	}

	// Get DACL offset
	daclOffset := binary.LittleEndian.Uint32(securityDescriptor[16:20])
	if daclOffset == 0 || int(daclOffset) >= len(securityDescriptor) {
		return nil
	}

	// Parse DACL
	dacl := securityDescriptor[daclOffset:]
	if len(dacl) < 8 {
		return nil
	}

	// ACL Header:
	// Byte 0: AclRevision
	// Byte 1: Sbz1
	// Bytes 2-3: AclSize (LE)
	// Bytes 4-5: AceCount (LE)
	// Bytes 6-7: Sbz2

	aclSize := binary.LittleEndian.Uint16(dacl[2:4])
	aceCount := binary.LittleEndian.Uint16(dacl[4:6])

	if int(aclSize) > len(dacl) {
		aclSize = uint16(len(dacl))
	}

	var aclEntries []types.ACLEntry

	// Parse each ACE
	aceOffset := 8 // ACL header is 8 bytes
	for i := 0; i < int(aceCount); i++ {
		if aceOffset >= int(aclSize) {
			break
		}

		ace := parseACE(dacl, aceOffset, objectDN)
		if ace != nil {
			aclEntries = append(aclEntries, *ace)
		}

		// Move to next ACE (get size from ACE header)
		if aceOffset+4 > len(dacl) {
			break
		}
		aceSize := binary.LittleEndian.Uint16(dacl[aceOffset+2 : aceOffset+4])
		if aceSize == 0 {
			break
		}
		aceOffset += int(aceSize)
	}

	return aclEntries
}

// parseACE parses a single ACE from DACL
func parseACE(dacl []byte, offset int, objectDN string) *types.ACLEntry {
	if offset+8 > len(dacl) {
		return nil
	}

	aceType := dacl[offset]
	// aceFlags := dacl[offset+1]  // Not used currently
	accessMask := binary.LittleEndian.Uint32(dacl[offset+4 : offset+8])

	// We only care about ACCESS_ALLOWED and ACCESS_ALLOWED_OBJECT ACEs
	if aceType != aceTypeAccessAllowed && aceType != aceTypeAccessAllowedObject {
		return nil
	}

	sidOffset := 8 // Standard ACE: type(1) + flags(1) + size(2) + mask(4)
	var objectType string

	// Handle Object ACEs (have optional GUIDs before SID)
	if aceType == aceTypeAccessAllowedObject {
		if offset+12 > len(dacl) {
			return nil
		}
		objectFlags := binary.LittleEndian.Uint32(dacl[offset+8 : offset+12])
		sidOffset = 12 // Object ACE: + flags(4)

		// If ACE_OBJECT_TYPE_PRESENT flag is set, there's a GUID
		if (objectFlags & aceObjectTypePresent) != 0 {
			if offset+sidOffset+16 > len(dacl) {
				return nil
			}
			objectType = parseGUID(dacl, offset+sidOffset)
			sidOffset += 16 // GUID is 16 bytes
		}

		// If ACE_INHERITED_OBJECT_TYPE_PRESENT flag is set, skip inherited GUID
		if (objectFlags & aceInheritedObjectTypePresent) != 0 {
			sidOffset += 16
		}
	}

	// Parse SID
	if offset+sidOffset >= len(dacl) {
		return nil
	}
	sid := parseSID(dacl, offset+sidOffset)

	return &types.ACLEntry{
		ObjectDN:   objectDN,
		Trustee:    sid,
		AccessMask: int(accessMask),
		AceType:    aceTypeToString(aceType),
		ObjectType: objectType,
	}
}

// parseSID parses Windows SID from binary format
func parseSID(buffer []byte, offset int) string {
	if offset+8 > len(buffer) {
		return "S-1-0-0"
	}

	revision := buffer[offset]
	subAuthorityCount := buffer[offset+1]

	// Sanity check
	if subAuthorityCount > 15 || offset+8+int(subAuthorityCount)*4 > len(buffer) {
		return "S-1-0-0"
	}

	// Read identifier authority (6 bytes, big-endian)
	// It's stored as a 48-bit big-endian value
	var identifierAuthority uint64
	for i := 0; i < 6; i++ {
		identifierAuthority = (identifierAuthority << 8) | uint64(buffer[offset+2+i])
	}

	// Build SID string
	sid := fmt.Sprintf("S-%d-%d", revision, identifierAuthority)

	// Read sub-authorities (4 bytes each, little-endian)
	subAuthOffset := offset + 8
	for i := 0; i < int(subAuthorityCount); i++ {
		subAuth := binary.LittleEndian.Uint32(buffer[subAuthOffset : subAuthOffset+4])
		sid += fmt.Sprintf("-%d", subAuth)
		subAuthOffset += 4
	}

	return sid
}

// parseGUID parses GUID from binary format to string
func parseGUID(buffer []byte, offset int) string {
	if offset+16 > len(buffer) {
		return "00000000-0000-0000-0000-000000000000"
	}

	// GUID format: Data1 (4 bytes LE) - Data2 (2 bytes LE) - Data3 (2 bytes LE) - Data4 (8 bytes)
	data1 := binary.LittleEndian.Uint32(buffer[offset : offset+4])
	data2 := binary.LittleEndian.Uint16(buffer[offset+4 : offset+6])
	data3 := binary.LittleEndian.Uint16(buffer[offset+6 : offset+8])

	// Data4 is 8 bytes: first 2 bytes + last 6 bytes
	data4High := buffer[offset+8 : offset+10]
	data4Low := buffer[offset+10 : offset+16]

	return fmt.Sprintf("%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		data1, data2, data3,
		data4High[0], data4High[1],
		data4Low[0], data4Low[1], data4Low[2], data4Low[3], data4Low[4], data4Low[5])
}

// aceTypeToString converts ACE type enum to string
func aceTypeToString(aceType byte) string {
	switch aceType {
	case aceTypeAccessAllowed:
		return "ACCESS_ALLOWED"
	case aceTypeAccessDenied:
		return "ACCESS_DENIED"
	case aceTypeSystemAudit:
		return "SYSTEM_AUDIT"
	case aceTypeAccessAllowedObject:
		return "ACCESS_ALLOWED_OBJECT"
	case aceTypeAccessDeniedObject:
		return "ACCESS_DENIED_OBJECT"
	case aceTypeSystemAuditObject:
		return "SYSTEM_AUDIT_OBJECT"
	default:
		return fmt.Sprintf("UNKNOWN_%d", aceType)
	}
}
