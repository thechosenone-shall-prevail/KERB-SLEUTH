package triage

import (
	"testing"
	"time"

	"github.com/yourusername/kerb-sleuth/pkg/krb"
)

func TestScoreCandidates(t *testing.T) {
	cfg := DefaultConfig()

	// Test AS-REP candidate
	asrepCandidates := []krb.Candidate{
		{
			SamAccountName: "testuser",
			Type:           "ASREP",
			PwdLastSet:     time.Now().Add(-100 * 24 * time.Hour), // Old password
			MemberOf:       []string{"CN=Domain Admins"},
		},
	}

	// Test Kerberoast candidate
	kerbCandidates := []krb.Candidate{
		{
			SamAccountName: "sqlsvc",
			Type:           "KERBEROAST",
			SPNs:           []string{"MSSQLSvc/sql.local"},
			PwdLastSet:     time.Now().Add(-30 * 24 * time.Hour), // Recent password
			MemberOf:       []string{"CN=Service Accounts"},
		},
	}

	scored := ScoreCandidates(asrepCandidates, kerbCandidates, cfg)

	if len(scored) != 2 {
		t.Errorf("Expected 2 scored candidates, got %d", len(scored))
	}

	// Find AS-REP candidate
	var asrepScore int
	var kerbScore int

	for _, candidate := range scored {
		if candidate.Type == "ASREP" {
			asrepScore = candidate.Score
		} else if candidate.Type == "KERBEROAST" {
			kerbScore = candidate.Score
		}
	}

	// AS-REP should have higher score due to old password and admin group
	expectedASREP := cfg.Weights.ASREPBase + cfg.Weights.ASREPPreauth +
		cfg.Weights.ASREPPwdOld + cfg.Weights.ASREPAdminGroup

	if asrepScore != expectedASREP {
		t.Errorf("Expected AS-REP score %d, got %d", expectedASREP, asrepScore)
	}

	// Kerberoast should have base score + SPN
	expectedKerb := cfg.Weights.KerberoastBase + cfg.Weights.KerberoastSPN

	if kerbScore != expectedKerb {
		t.Errorf("Expected Kerberoast score %d, got %d", expectedKerb, kerbScore)
	}
}

func TestIsInAdminGroup(t *testing.T) {
	adminGroups := []string{"CN=Domain Admins", "CN=Enterprise Admins"}

	testCases := []struct {
		userGroups []string
		expected   bool
	}{
		{[]string{"CN=Domain Users"}, false},
		{[]string{"CN=Domain Admins,DC=corp,DC=local"}, true},
		{[]string{"cn=domain admins"}, true}, // Case insensitive
		{[]string{"CN=Enterprise Admins"}, true},
		{[]string{"CN=Regular Group", "CN=Domain Admins"}, true},
	}

	for _, tc := range testCases {
		result := isInAdminGroup(tc.userGroups, adminGroups)
		if result != tc.expected {
			t.Errorf("For groups %v, expected %v, got %v", tc.userGroups, tc.expected, result)
		}
	}
}

func TestGetSeverity(t *testing.T) {
	thresholds := Thresholds{High: 80, Medium: 50}

	testCases := []struct {
		score    int
		expected string
	}{
		{90, "Severity: High"},
		{80, "Severity: High"},
		{60, "Severity: Medium"},
		{50, "Severity: Medium"},
		{30, "Severity: Low"},
	}

	for _, tc := range testCases {
		result := getSeverity(tc.score, thresholds)
		if result != tc.expected {
			t.Errorf("For score %d, expected %s, got %s", tc.score, tc.expected, result)
		}
	}
}
