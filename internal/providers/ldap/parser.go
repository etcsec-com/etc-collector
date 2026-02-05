package ldap

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/etcsec-com/etc-collector/pkg/types"
)

// LDAP attribute names
var userAttributes = []string{
	"distinguishedName",
	"sAMAccountName",
	"userPrincipalName",
	"displayName",
	"description",
	"mail",
	"userAccountControl",
	"adminCount",
	"whenCreated",
	"lastLogon",
	"lastLogonTimestamp",
	"pwdLastSet",
	"accountExpires",
	"logonCount",
	"badPwdCount",
	"primaryGroupID",
	"memberOf",
	"sIDHistory",
	"servicePrincipalName",
	"objectSid",
}

var groupAttributes = []string{
	"distinguishedName",
	"sAMAccountName",
	"description",
	"groupType",
	"adminCount",
	"member",
	"memberOf",
	"objectSid",
}

var computerAttributes = []string{
	"distinguishedName",
	"sAMAccountName",
	"dNSHostName",
	"operatingSystem",
	"operatingSystemVersion",
	"description",
	"userAccountControl",
	"whenCreated",
	"lastLogon",
	"lastLogonTimestamp",
	"pwdLastSet",
	"servicePrincipalName",
	"memberOf",
	"objectSid",
	"ms-Mcs-AdmPwd",
	"ms-Mcs-AdmPwdExpirationTime",
}

// User Account Control flags
const (
	UAC_ACCOUNTDISABLE         = 0x0002
	UAC_LOCKOUT                = 0x0010
	UAC_PASSWD_NOTREQD         = 0x0020
	UAC_PASSWD_CANT_CHANGE     = 0x0040
	UAC_NORMAL_ACCOUNT         = 0x0200
	UAC_DONT_EXPIRE_PASSWD     = 0x10000
	UAC_SMARTCARD_REQUIRED     = 0x40000
	UAC_TRUSTED_FOR_DELEGATION = 0x80000
	UAC_NOT_DELEGATED          = 0x100000
	UAC_USE_DES_KEY_ONLY       = 0x200000
	UAC_DONT_REQ_PREAUTH       = 0x400000
	UAC_PASSWORD_EXPIRED       = 0x800000
	UAC_TRUSTED_TO_AUTH_FOR_DELEGATION = 0x1000000
)

// parseUser parses an LDAP entry into a User
func parseUser(entry *ldap.Entry) types.User {
	uac := getIntAttr(entry, "userAccountControl")

	user := types.User{
		DN:                    entry.DN,
		SAMAccountName:        entry.GetAttributeValue("sAMAccountName"),
		UserPrincipalName:     entry.GetAttributeValue("userPrincipalName"),
		DisplayName:           entry.GetAttributeValue("displayName"),
		Description:           entry.GetAttributeValue("description"),
		Mail:                  entry.GetAttributeValue("mail"),
		UserAccountControl:    uac,
		AdminCount:            entry.GetAttributeValue("adminCount") == "1",
		Created:               parseADTime(entry.GetAttributeValue("whenCreated")),
		LastLogon:             parseFileTime(entry.GetAttributeValue("lastLogon")),
		LastLogonTimestamp:    parseFileTime(entry.GetAttributeValue("lastLogonTimestamp")),
		PasswordLastSet:       parseFileTime(entry.GetAttributeValue("pwdLastSet")),
		AccountExpires:        parseFileTime(entry.GetAttributeValue("accountExpires")),
		LogonCount:            getIntAttr(entry, "logonCount"),
		BadPasswordCount:      getIntAttr(entry, "badPwdCount"),
		PrimaryGroupID:        getIntAttr(entry, "primaryGroupID"),
		MemberOf:              entry.GetAttributeValues("memberOf"),
		SIDHistory:            decodeSIDHistory(entry.GetRawAttributeValues("sIDHistory")),
		ServicePrincipalNames: entry.GetAttributeValues("servicePrincipalName"),
		ObjectSID:             decodeSID(entry.GetRawAttributeValue("objectSid")),
	}

	// Parse UAC flags
	user.Disabled = (uac & UAC_ACCOUNTDISABLE) != 0
	user.LockedOut = (uac & UAC_LOCKOUT) != 0
	user.PasswordNeverExpires = (uac & UAC_DONT_EXPIRE_PASSWD) != 0
	user.PasswordNotRequired = (uac & UAC_PASSWD_NOTREQD) != 0
	user.PasswordExpired = (uac & UAC_PASSWORD_EXPIRED) != 0
	user.CannotChangePassword = (uac & UAC_PASSWD_CANT_CHANGE) != 0
	user.DoesNotRequirePreAuth = (uac & UAC_DONT_REQ_PREAUTH) != 0
	user.TrustedForDelegation = (uac & UAC_TRUSTED_FOR_DELEGATION) != 0

	return user
}

// parseGroup parses an LDAP entry into a Group
func parseGroup(entry *ldap.Entry) types.Group {
	return types.Group{
		DN:             entry.DN,
		SAMAccountName: entry.GetAttributeValue("sAMAccountName"),
		Description:    entry.GetAttributeValue("description"),
		GroupType:      getIntAttr(entry, "groupType"),
		AdminCount:     entry.GetAttributeValue("adminCount") == "1",
		Members:        entry.GetAttributeValues("member"),
		MemberOf:       entry.GetAttributeValues("memberOf"),
		ObjectSID:      decodeSID(entry.GetRawAttributeValue("objectSid")),
	}
}

// parseComputer parses an LDAP entry into a Computer
func parseComputer(entry *ldap.Entry) types.Computer {
	uac := getIntAttr(entry, "userAccountControl")

	computer := types.Computer{
		DN:                     entry.DN,
		SAMAccountName:         entry.GetAttributeValue("sAMAccountName"),
		DNSHostName:            entry.GetAttributeValue("dNSHostName"),
		OperatingSystem:        entry.GetAttributeValue("operatingSystem"),
		OperatingSystemVersion: entry.GetAttributeValue("operatingSystemVersion"),
		Description:            entry.GetAttributeValue("description"),
		UserAccountControl:     uac,
		Created:                parseADTime(entry.GetAttributeValue("whenCreated")),
		LastLogon:              parseFileTime(entry.GetAttributeValue("lastLogon")),
		LastLogonTimestamp:     parseFileTime(entry.GetAttributeValue("lastLogonTimestamp")),
		PasswordLastSet:        parseFileTime(entry.GetAttributeValue("pwdLastSet")),
		ServicePrincipalNames:  entry.GetAttributeValues("servicePrincipalName"),
		MemberOf:               entry.GetAttributeValues("memberOf"),
		ObjectSID:              decodeSID(entry.GetRawAttributeValue("objectSid")),
		LAPSPassword:           entry.GetAttributeValue("ms-Mcs-AdmPwd"),
	}

	// Parse LAPS expiry
	if lapsExpiry := entry.GetAttributeValue("ms-Mcs-AdmPwdExpirationTime"); lapsExpiry != "" {
		computer.LAPSPasswordExpiry = parseFileTime(lapsExpiry)
	}

	// Parse UAC flags
	computer.Disabled = (uac & UAC_ACCOUNTDISABLE) != 0
	computer.TrustedForDelegation = (uac & UAC_TRUSTED_FOR_DELEGATION) != 0
	computer.TrustedToAuthForDelegation = (uac & UAC_TRUSTED_TO_AUTH_FOR_DELEGATION) != 0

	return computer
}

// getIntAttr gets an integer attribute value
func getIntAttr(entry *ldap.Entry, name string) int {
	val := entry.GetAttributeValue(name)
	if val == "" {
		return 0
	}
	i, _ := strconv.Atoi(val)
	return i
}

// parseADTime parses AD generalized time format (YYYYMMDDHHmmss.0Z)
func parseADTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}

	// Remove trailing .0Z if present
	s = strings.TrimSuffix(s, ".0Z")
	s = strings.TrimSuffix(s, "Z")

	// Try parsing
	t, err := time.Parse("20060102150405", s)
	if err != nil {
		return time.Time{}
	}
	return t
}

// parseFileTime parses Windows FILETIME (100-nanosecond intervals since 1601-01-01)
func parseFileTime(s string) time.Time {
	if s == "" || s == "0" {
		return time.Time{}
	}

	// Parse as int64
	ft, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return time.Time{}
	}

	// Never expires
	if ft == 9223372036854775807 {
		return time.Time{}
	}

	// Convert to Unix time
	// FILETIME epoch is 1601-01-01, Unix epoch is 1970-01-01
	// Difference is 116444736000000000 100-nanosecond intervals
	const epochDiff = 116444736000000000
	if ft < epochDiff {
		return time.Time{}
	}

	// Convert to nanoseconds then to time
	nsec := (ft - epochDiff) * 100
	return time.Unix(0, nsec)
}

// decodeSID decodes a binary SID to string format
func decodeSID(data []byte) string {
	if len(data) < 8 {
		return ""
	}

	revision := data[0]
	subAuthCount := int(data[1])

	// Identifier authority (6 bytes, big endian)
	var authority uint64
	for i := 2; i < 8; i++ {
		authority = (authority << 8) | uint64(data[i])
	}

	// Build SID string
	sid := fmt.Sprintf("S-%d-%d", revision, authority)

	// Sub-authorities (4 bytes each, little endian)
	offset := 8
	for i := 0; i < subAuthCount && offset+4 <= len(data); i++ {
		subAuth := binary.LittleEndian.Uint32(data[offset:])
		sid += fmt.Sprintf("-%d", subAuth)
		offset += 4
	}

	return sid
}

// decodeSIDHistory decodes multiple SIDs from sIDHistory
func decodeSIDHistory(data [][]byte) []string {
	sids := make([]string, 0, len(data))
	for _, d := range data {
		if sid := decodeSID(d); sid != "" {
			sids = append(sids, sid)
		}
	}
	return sids
}
