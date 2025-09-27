package krb

import (
	"testing"
	"time"

	"github.com/thechosenone-shall-prevail/kerb-sleuth/pkg/ingest"
)

func TestFindASREPCandidates(t *testing.T) {
	users := []ingest.User{
		{
			SamAccountName:        "normaluser",
			DoesNotRequirePreAuth: false,
			UserAccountControl:    512,
		},
		{
			SamAccountName:        "asrepuser",
			DoesNotRequirePreAuth: true,
			UserAccountControl:    512,
			PwdLastSet:            time.Now().Add(-100 * 24 * time.Hour),
		},
		{
			SamAccountName:     "machine$",
			UserAccountControl: 4096,
		},
		{
			SamAccountName:     "disabled",
			UserAccountControl: 514, // Disabled account
		},
	}

	candidates := FindASREPCandidates(users)

	if len(candidates) != 1 {
		t.Errorf("Expected 1 AS-REP candidate, got %d", len(candidates))
	}

	if candidates[0].SamAccountName != "asrepuser" {
		t.Errorf("Expected asrepuser, got %s", candidates[0].SamAccountName)
	}

	if candidates[0].Type != "ASREP" {
		t.Errorf("Expected type ASREP, got %s", candidates[0].Type)
	}
}

func TestFindKerberoastCandidates(t *testing.T) {
	users := []ingest.User{
		{
			SamAccountName:        "normaluser",
			UserAccountControl:    512,
			ServicePrincipalNames: []string{},
		},
		{
			SamAccountName:        "sqlsvc",
			UserAccountControl:    512,
			ServicePrincipalNames: []string{"MSSQLSvc/sql.local:1433", "MSSQLSvc/sql.local"},
			PwdLastSet:            time.Now().Add(-100 * 24 * time.Hour),
		},
		{
			SamAccountName:        "machine$",
			UserAccountControl:    4096,
			ServicePrincipalNames: []string{"HOST/machine.local"},
		},
		{
			SamAccountName:        "disabled",
			UserAccountControl:    514, // Disabled
			ServicePrincipalNames: []string{"HTTP/web.local"},
		},
	}

	candidates := FindKerberoastCandidates(users)

	if len(candidates) != 1 {
		t.Errorf("Expected 1 Kerberoast candidate, got %d", len(candidates))
	}

	if candidates[0].SamAccountName != "sqlsvc" {
		t.Errorf("Expected sqlsvc, got %s", candidates[0].SamAccountName)
	}

	if candidates[0].Type != "KERBEROAST" {
		t.Errorf("Expected type KERBEROAST, got %s", candidates[0].Type)
	}

	if len(candidates[0].SPNs) != 2 {
		t.Errorf("Expected 2 SPNs, got %d", len(candidates[0].SPNs))
	}
}

func TestHasAdminGroup(t *testing.T) {
	testCases := []struct {
		groups   []string
		expected bool
	}{
		{[]string{"CN=Domain Users"}, false},
		{[]string{"CN=Domain Admins"}, true},
		{[]string{"cn=domain admins"}, true}, // Case insensitive
		{[]string{"CN=Enterprise Admins,DC=corp,DC=local"}, true},
		{[]string{"CN=Backup Operators"}, true},
		{[]string{"CN=Regular Group"}, false},
	}

	for _, tc := range testCases {
		result := hasAdminGroup(tc.groups)
		if result != tc.expected {
			t.Errorf("For groups %v, expected %v, got %v", tc.groups, tc.expected, result)
		}
	}
}
