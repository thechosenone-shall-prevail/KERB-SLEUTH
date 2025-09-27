package ingest

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseCSV(t *testing.T) {
	// Create test CSV
	csvContent := `sAMAccountName,distinguishedName,DoesNotRequirePreAuth,userAccountControl,servicePrincipalName
testuser,CN=testuser;OU=Users,True,4260352,
sqlsvc,CN=sqlsvc;OU=Services,False,512,MSSQLSvc/sql01.local:1433;MSSQLSvc/sql01.local
machine$,CN=machine;OU=Computers,False,4096,HOST/machine.local`

	tmpFile := filepath.Join(t.TempDir(), "test.csv")
	if err := os.WriteFile(tmpFile, []byte(csvContent), 0644); err != nil {
		t.Fatal(err)
	}

	users, err := ParseAD(tmpFile)
	if err != nil {
		t.Fatalf("ParseAD failed: %v", err)
	}

	if len(users) != 3 {
		t.Errorf("Expected 3 users, got %d", len(users))
	}

	// Check first user (AS-REP candidate)
	if !users[0].DoesNotRequirePreAuth {
		t.Error("First user should have DoesNotRequirePreAuth=true")
	}

	// Check second user (Kerberoast candidate)
	if len(users[1].ServicePrincipalNames) != 2 {
		t.Errorf("Expected 2 SPNs for sqlsvc, got %d", len(users[1].ServicePrincipalNames))
	}

	// Check machine account
	if users[2].SamAccountName != "machine$" {
		t.Error("Machine account name not parsed correctly")
	}
}

func TestParseCSVVariants(t *testing.T) {
	testCases := []struct {
		name    string
		header  string
		data    string
		wantLen int
	}{
		{
			name:    "lowercase_headers",
			header:  "samaccountname,useraccountcontrol,serviceprincipalname",
			data:    "user1,512,\nuser2,4260352,HTTP/web.local",
			wantLen: 2,
		},
		{
			name:    "mixed_case_headers",
			header:  "sAMAccountName,UserAccountControl,ServicePrincipalName",
			data:    "user3,512,\nuser4,512,LDAP/dc.local",
			wantLen: 2,
		},
		{
			name:    "spaces_in_headers",
			header:  "SAM Account Name, User Account Control, Service Principal Name",
			data:    "user5, 512,\nuser6, 512, HTTP/app.local",
			wantLen: 2,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			csvContent := tc.header + "\n" + tc.data
			tmpFile := filepath.Join(t.TempDir(), "test.csv")
			if err := os.WriteFile(tmpFile, []byte(csvContent), 0644); err != nil {
				t.Fatal(err)
			}

			users, err := ParseAD(tmpFile)
			if err != nil {
				t.Fatalf("ParseAD failed: %v", err)
			}

			if len(users) != tc.wantLen {
				t.Errorf("Expected %d users, got %d", tc.wantLen, len(users))
			}
		})
	}
}

func TestParseTime(t *testing.T) {
	testCases := []struct {
		input    string
		expected bool // whether we expect a valid time
	}{
		{"1622505600", true},           // Unix timestamp
		{"2021-06-01T10:00:00Z", true}, // ISO format
		{"2021-06-01", true},           // Date only
		{"invalid", false},             // Invalid
		{"", false},                    // Empty
	}

	for _, tc := range testCases {
		t.Run(tc.input, func(t *testing.T) {
			result := parseTime(tc.input)
			isEmpty := result.IsZero()

			if tc.expected && isEmpty {
				t.Errorf("Expected valid time for %s, got zero time", tc.input)
			}
			if !tc.expected && !isEmpty {
				t.Errorf("Expected zero time for %s, got %v", tc.input, result)
			}
		})
	}
}

func TestParseSPNs(t *testing.T) {
	testCases := []struct {
		input    string
		expected []string
	}{
		{"", nil},
		{"HTTP/web.local", []string{"HTTP/web.local"}},
		{"HTTP/web.local;LDAP/dc.local", []string{"HTTP/web.local", "LDAP/dc.local"}},
		{"HTTP/web.local,LDAP/dc.local", []string{"HTTP/web.local", "LDAP/dc.local"}},
		{"HTTP/web.local|LDAP/dc.local", []string{"HTTP/web.local", "LDAP/dc.local"}},
	}

	for _, tc := range testCases {
		t.Run(tc.input, func(t *testing.T) {
			result := parseSPNs(tc.input)

			if len(result) != len(tc.expected) {
				t.Errorf("Expected %d SPNs, got %d", len(tc.expected), len(result))
				return
			}

			for i, spn := range result {
				if spn != tc.expected[i] {
					t.Errorf("Expected SPN %s, got %s", tc.expected[i], spn)
				}
			}
		})
	}
}
