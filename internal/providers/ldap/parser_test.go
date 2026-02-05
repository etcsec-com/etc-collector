package ldap

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestParseADTime(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected time.Time
	}{
		{
			name:     "standard format",
			input:    "20240115143022.0Z",
			expected: time.Date(2024, 1, 15, 14, 30, 22, 0, time.UTC),
		},
		{
			name:     "without .0Z suffix",
			input:    "20240115143022Z",
			expected: time.Date(2024, 1, 15, 14, 30, 22, 0, time.UTC),
		},
		{
			name:     "empty string",
			input:    "",
			expected: time.Time{},
		},
		{
			name:     "invalid format",
			input:    "invalid",
			expected: time.Time{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseADTime(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestParseFileTime(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		isZero   bool
	}{
		{
			name:   "valid filetime",
			input:  "133500000000000000", // Some valid timestamp
			isZero: false,
		},
		{
			name:   "zero",
			input:  "0",
			isZero: true,
		},
		{
			name:   "empty",
			input:  "",
			isZero: true,
		},
		{
			name:   "never expires",
			input:  "9223372036854775807",
			isZero: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseFileTime(tt.input)
			assert.Equal(t, tt.isZero, result.IsZero())
		})
	}
}

func TestDecodeSID(t *testing.T) {
	tests := []struct {
		name       string
		input      []byte
		wantPrefix string
		wantEmpty  bool
	}{
		{
			name: "valid SID - everyone",
			// S-1-1-0 (Everyone)
			input: []byte{
				0x01,                               // Revision
				0x01,                               // Sub-authority count (1)
				0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // Identifier authority (1)
				0x00, 0x00, 0x00, 0x00,             // Sub-auth 1: 0
			},
			wantPrefix: "S-1-1-0",
			wantEmpty:  false,
		},
		{
			name: "valid SID - NT Authority",
			// S-1-5-... (NT Authority)
			input: []byte{
				0x01,                               // Revision
				0x02,                               // Sub-authority count (2)
				0x00, 0x00, 0x00, 0x00, 0x00, 0x05, // Identifier authority (5)
				0x20, 0x00, 0x00, 0x00,             // Sub-auth 1: 32
				0x20, 0x02, 0x00, 0x00,             // Sub-auth 2: 544
			},
			wantPrefix: "S-1-5-32-544",
			wantEmpty:  false,
		},
		{
			name:      "empty",
			input:     []byte{},
			wantEmpty: true,
		},
		{
			name:      "too short",
			input:     []byte{0x01, 0x01, 0x00},
			wantEmpty: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := decodeSID(tt.input)
			if tt.wantEmpty {
				assert.Empty(t, result)
			} else {
				assert.Equal(t, tt.wantPrefix, result)
			}
		})
	}
}

func TestDecodeSIDHistory(t *testing.T) {
	// Create a valid SID bytes for testing
	validSID := []byte{
		0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
		0x20, 0x00, 0x00, 0x00, 0x20, 0x02, 0x00, 0x00,
	}

	tests := []struct {
		name     string
		input    [][]byte
		expected int
	}{
		{
			name:     "empty",
			input:    [][]byte{},
			expected: 0,
		},
		{
			name:     "single SID",
			input:    [][]byte{validSID},
			expected: 1,
		},
		{
			name:     "multiple SIDs",
			input:    [][]byte{validSID, validSID, validSID},
			expected: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := decodeSIDHistory(tt.input)
			assert.Len(t, result, tt.expected)
		})
	}
}

func TestUACFlags(t *testing.T) {
	// Test that UAC constants are correct
	assert.Equal(t, 0x0002, UAC_ACCOUNTDISABLE)
	assert.Equal(t, 0x0010, UAC_LOCKOUT)
	assert.Equal(t, 0x10000, UAC_DONT_EXPIRE_PASSWD)
	assert.Equal(t, 0x400000, UAC_DONT_REQ_PREAUTH)
	assert.Equal(t, 0x80000, UAC_TRUSTED_FOR_DELEGATION)
}
