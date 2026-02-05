package types

import "time"

// User represents an Active Directory user
type User struct {
	DN                    string    `json:"dn"`
	SAMAccountName        string    `json:"sAMAccountName"`
	UserPrincipalName     string    `json:"userPrincipalName,omitempty"`
	DisplayName           string    `json:"displayName,omitempty"`
	Description           string    `json:"description,omitempty"`
	Mail                  string    `json:"mail,omitempty"`
	Disabled              bool      `json:"disabled"`
	LockedOut             bool      `json:"lockedOut"`
	PasswordNeverExpires  bool      `json:"passwordNeverExpires"`
	PasswordNotRequired   bool      `json:"passwordNotRequired"`
	PasswordExpired       bool      `json:"passwordExpired"`
	CannotChangePassword  bool      `json:"cannotChangePassword"`
	DoesNotRequirePreAuth bool      `json:"doesNotRequirePreAuth"`
	TrustedForDelegation       bool      `json:"trustedForDelegation"`
	TrustedToAuthForDelegation bool      `json:"trustedToAuthForDelegation"`
	UseDesKeyOnly              bool      `json:"useDesKeyOnly"`
	AdminCount                 bool      `json:"adminCount"`
	Created               time.Time `json:"created"`
	LastLogon             time.Time `json:"lastLogon"`
	LastLogonTimestamp    time.Time `json:"lastLogonTimestamp"`
	PasswordLastSet       time.Time `json:"passwordLastSet"`
	AccountExpires        time.Time `json:"accountExpires,omitempty"`
	LogonCount            int       `json:"logonCount"`
	BadPasswordCount      int       `json:"badPasswordCount"`
	PrimaryGroupID        int       `json:"primaryGroupId"`
	UserAccountControl    int       `json:"userAccountControl"`
	MemberOf              []string  `json:"memberOf,omitempty"`
	SIDHistory            []string  `json:"sidHistory,omitempty"`
	ServicePrincipalNames     []string  `json:"servicePrincipalNames,omitempty"`
	AllowedToDelegateTo       []string  `json:"msDS-AllowedToDelegateTo,omitempty"`
	SupportedEncryptionTypes  int       `json:"msDS-SupportedEncryptionTypes,omitempty"`
	ObjectSID                 string    `json:"objectSid"`
	// Additional fields for advanced detectors
	ScriptPath                          string `json:"scriptPath,omitempty"`
	KeyCredentialLink                   []byte `json:"msDS-KeyCredentialLink,omitempty"`
	AllowedToActOnBehalfOfOtherIdentity []byte `json:"msDS-AllowedToActOnBehalfOfOtherIdentity,omitempty"`
	HasSeEnableDelegationPrivilege      bool   `json:"hasSeEnableDelegationPrivilege,omitempty"`
	HasDCSyncRights                     bool   `json:"hasDCSyncRights,omitempty"`
	// ACL analysis fields
	HasWriteDACL                        bool   `json:"hasWriteDACL,omitempty"`
	HasGenericAll                       bool   `json:"hasGenericAll,omitempty"`
	HasWriteOwner                       bool   `json:"hasWriteOwner,omitempty"`
}

// Enabled returns true if the user account is not disabled
func (u User) Enabled() bool {
	return !u.Disabled
}

// Group represents an Active Directory group
type Group struct {
	DN                string   `json:"dn"`
	DistinguishedName string   `json:"distinguishedName,omitempty"` // Alias for DN
	CN                string   `json:"cn,omitempty"`
	SAMAccountName    string   `json:"sAMAccountName"`
	DisplayName       string   `json:"displayName,omitempty"`
	Description       string   `json:"description,omitempty"`
	GroupType         int      `json:"groupType"`
	AdminCount        bool     `json:"adminCount"`
	Members           []string `json:"members,omitempty"`
	Member            []string `json:"member,omitempty"` // Alias for Members (raw LDAP attr)
	MemberOf          []string `json:"memberOf,omitempty"`
	ObjectSID         string   `json:"objectSid"`
}

// Computer represents an Active Directory computer
type Computer struct {
	DN                         string    `json:"dn"`
	DistinguishedName          string    `json:"distinguishedName,omitempty"` // Alias for DN
	SAMAccountName             string    `json:"sAMAccountName"`
	DNSHostName                string    `json:"dnsHostName,omitempty"`
	OperatingSystem            string    `json:"operatingSystem,omitempty"`
	OperatingSystemVersion     string    `json:"operatingSystemVersion,omitempty"`
	Description                string    `json:"description,omitempty"`
	Disabled                   bool      `json:"disabled"`
	TrustedForDelegation       bool      `json:"trustedForDelegation"`
	TrustedToAuthForDelegation bool      `json:"trustedToAuthForDelegation"`
	AdminCount                 bool      `json:"adminCount,omitempty"`
	Created                    time.Time `json:"created"`
	WhenChanged                time.Time `json:"whenChanged,omitempty"`
	LastLogon                  time.Time `json:"lastLogon"`
	LastLogonTimestamp         time.Time `json:"lastLogonTimestamp"`
	PasswordLastSet            time.Time `json:"passwordLastSet"`
	UserAccountControl         int       `json:"userAccountControl"`
	SupportedEncryptionTypes   int       `json:"msDS-SupportedEncryptionTypes,omitempty"`
	ServicePrincipalNames      []string  `json:"servicePrincipalNames,omitempty"`
	MemberOf                   []string  `json:"memberOf,omitempty"`
	AllowedToDelegateTo        []string  `json:"msDS-AllowedToDelegateTo,omitempty"`
	AllowedToActOnBehalfOfOtherIdentity []byte `json:"msDS-AllowedToActOnBehalfOfOtherIdentity,omitempty"`
	ObjectSID                  string    `json:"objectSid"`
	// Security analysis fields
	ReplicationRights          bool      `json:"replicationRights,omitempty"`  // Has DCSync rights
	DangerousACL               bool      `json:"dangerousACL,omitempty"`       // Has dangerous ACLs
	SMBSigningDisabled         bool      `json:"smbSigningDisabled,omitempty"` // SMB signing not required
	// LAPS fields
	LAPSPassword               string    `json:"lapsPassword,omitempty"` // Only if readable (legacy or Windows LAPS)
	LAPSPasswordExpiry         time.Time `json:"lapsPasswordExpiry,omitempty"`
	HasLegacyLAPS              bool      `json:"hasLegacyLAPS,omitempty"`  // ms-Mcs-AdmPwd or expiry exists
	HasWindowsLAPS             bool      `json:"hasWindowsLAPS,omitempty"` // msLAPS-Password or expiry exists
	LegacyLAPSPassword         string    `json:"legacyLapsPassword,omitempty"`
	WindowsLAPSPassword        string    `json:"windowsLapsPassword,omitempty"`
	LAPSPasswordExcessiveReaders    bool `json:"lapsPasswordExcessiveReaders,omitempty"`
	LAPSPasswordReadableByNonAdmins bool `json:"lapsPasswordReadableByNonAdmins,omitempty"`
}

// Enabled returns true if the computer account is not disabled
func (c Computer) Enabled() bool {
	return !c.Disabled
}

// GPO represents a Group Policy Object
type GPO struct {
	DN                string   `json:"dn"`
	DistinguishedName string   `json:"distinguishedName,omitempty"` // Alias for DN
	CN                string   `json:"cn,omitempty"`                // Common name (GUID format)
	Name              string   `json:"name"`
	DisplayName       string   `json:"displayName"`
	GUID              string   `json:"guid"`
	FilePath          string   `json:"filePath"`
	Enabled           bool     `json:"enabled"`
	UserEnabled       bool     `json:"userEnabled"`
	ComputerEnabled   bool     `json:"computerEnabled"`
	Flags             int      `json:"flags,omitempty"` // GPO flags (0=enabled, 1=user disabled, 2=computer disabled, 3=all disabled)
	HasWeakACL        bool     `json:"hasWeakACL,omitempty"` // True if non-admins have write access
	LinkedOUs         []string `json:"linkedOUs,omitempty"`
	CSEGuids          []string `json:"cseGuids,omitempty"` // Client-Side Extensions GUIDs
}

// Trust represents a domain trust
type Trust struct {
	Name                 string `json:"name,omitempty"` // Alias for TargetDomain
	SourceDomain         string `json:"sourceDomain"`
	TargetDomain         string `json:"targetDomain"`
	TrustType            string `json:"trustType"`      // Parent, Child, External, Forest
	TrustDirection       string `json:"trustDirection"` // Inbound, Outbound, Bidirectional
	Direction            string `json:"direction,omitempty"` // Alias for TrustDirection
	TrustDirectionInt    int    `json:"trustDirectionInt,omitempty"` // Numeric: 1=Inbound, 2=Outbound, 3=Bidirectional
	SIDFiltering         bool   `json:"sidFiltering"`
	SIDFilteringEnabled  bool   `json:"sidFilteringEnabled,omitempty"` // Alias
	SelectiveAuth        bool   `json:"selectiveAuth"`
	SelectiveAuthEnabled bool   `json:"selectiveAuthEnabled,omitempty"` // Alias
	// Encryption settings
	AESEnabled           bool   `json:"aesEnabled,omitempty"`
	RC4Enabled           bool   `json:"rc4Enabled,omitempty"`
	IsTransitive         bool   `json:"isTransitive,omitempty"`
	WhenCreated          string `json:"whenCreated,omitempty"`
}

// DomainInfo represents domain-level information
type DomainInfo struct {
	DN                 string `json:"dn"` // Alias for DomainDN
	DomainDN           string `json:"domainDN"`
	DomainSID          string `json:"domainSid"`
	DomainName         string `json:"domainName"`
	ForestName         string `json:"forestName"`
	FunctionalLevel    string `json:"functionalLevel"`
	FunctionalLevelInt int    `json:"functionalLevelInt,omitempty"` // Numeric version for comparisons
	ForestFunctionalLevel string `json:"forestFunctionalLevel"`
	DomainControllers  []string `json:"domainControllers"`

	// Policy settings - Password Policy
	MinPasswordLength     int `json:"minPasswordLength"`
	MinPwdLength          int `json:"minPwdLength,omitempty"` // Alias
	PasswordHistoryLength int `json:"passwordHistoryLength"`
	PwdHistoryLength      int `json:"pwdHistoryLength,omitempty"` // Alias
	MaxPasswordAge        int `json:"maxPasswordAge"` // days
	MaxPwdAge             int `json:"maxPwdAge,omitempty"` // Alias (days)
	MinPwdAge             int `json:"minPwdAge,omitempty"` // Minimum password age (days)

	// Policy settings - Lockout
	LockoutThreshold      int `json:"lockoutThreshold"`
	LockoutDuration       int `json:"lockoutDuration"` // minutes

	// Policy settings - Kerberos
	MaxTicketAge          int `json:"maxTicketAge,omitempty"` // hours
	MaxRenewAge           int `json:"maxRenewAge,omitempty"`  // days
	MachineAccountQuota   int `json:"machineAccountQuota"`

	// Security settings
	AnonymousLDAPAllowed  bool   `json:"anonymousLdapAllowed,omitempty"`
	RecycleBinEnabled     bool   `json:"recycleBinEnabled,omitempty"`
	AdminSDHolderModified bool   `json:"adminSdHolderModified,omitempty"`
	DsHeuristics          string `json:"dsHeuristics,omitempty"`
	LDAPSigningRequired   bool   `json:"ldapSigningRequired,omitempty"`
	ChannelBindingRequired bool  `json:"channelBindingRequired,omitempty"`

	// Statistics
	ForeignSecurityPrincipalsCount int `json:"foreignSecurityPrincipalsCount,omitempty"`
}

// CertTemplate represents an AD CS certificate template
type CertTemplate struct {
	DN                      string   `json:"dn"`
	Name                    string   `json:"name"`
	DisplayName             string   `json:"displayName"`
	OID                     string   `json:"oid"`
	EnrollmentFlag          int      `json:"enrollmentFlag"`
	RequiresManagerApproval bool     `json:"requiresManagerApproval"`
	AuthorizedSignatures    int      `json:"authorizedSignatures"`
	SchemaVersion           int      `json:"schemaVersion"`
	ValidityPeriod          string   `json:"validityPeriod"`
	ExtendedKeyUsage        []string `json:"extendedKeyUsage,omitempty"`
	SubjectNameFlag         int      `json:"subjectNameFlag"`
	CertificateNameFlag     int      `json:"certificateNameFlag,omitempty"` // msPKI-Certificate-Name-Flag
	// Security analysis fields
	HasWeakEnrollmentACL    bool     `json:"hasWeakEnrollmentACL,omitempty"`
	HasGenericAllPermission bool     `json:"hasGenericAllPermission,omitempty"`
	HasWeakACL              bool     `json:"hasWeakACL,omitempty"`
}

// ACE represents an Access Control Entry
type ACE struct {
	Principal   string `json:"principal"`
	PrincipalSID string `json:"principalSid"`
	AccessMask  int    `json:"accessMask"`
	AceType     string `json:"aceType"`
	ObjectType  string `json:"objectType,omitempty"`
	InheritedObjectType string `json:"inheritedObjectType,omitempty"`
	IsInherited bool   `json:"isInherited"`
}

// ACLEntry represents an Access Control List entry with its target object
type ACLEntry struct {
	ObjectDN   string `json:"objectDn"`             // DN of the object the ACE applies to
	Trustee    string `json:"trustee"`              // SID or name of the principal
	AccessMask int    `json:"accessMask"`           // Access mask bits
	AceType    string `json:"aceType"`              // Type of ACE (allow, deny)
	ObjectType string `json:"objectType,omitempty"` // GUID of the object type or property
}
