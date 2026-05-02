package output

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/thechosenone-shall-prevail/KERB-SLEUTH/pkg/krb"
)

func TestWriteJSON(t *testing.T) {
	results := Results{
		Summary: Summary{
			TotalUsers:           10,
			ASREPCandidates:      2,
			KerberoastCandidates: 3,
		},
		Candidates: []krb.Candidate{
			{
				SamAccountName: "testuser",
				Type:           "ASREP",
				Score:          85,
				Reasons:        []string{"DoesNotRequirePreAuth", "Severity: High"},
			},
		},
	}

	tmpFile := filepath.Join(t.TempDir(), "test.json")

	err := WriteJSON(tmpFile, results)
	if err != nil {
		t.Fatalf("WriteJSON failed: %v", err)
	}

	// Verify file exists and contains valid JSON
	data, err := os.ReadFile(tmpFile)
	if err != nil {
		t.Fatalf("Failed to read output file: %v", err)
	}

	var parsed Results
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Output is not valid JSON: %v", err)
	}

	if parsed.Summary.TotalUsers != 10 {
		t.Errorf("Expected 10 total users, got %d", parsed.Summary.TotalUsers)
	}

	if len(parsed.Candidates) != 1 {
		t.Errorf("Expected 1 candidate, got %d", len(parsed.Candidates))
	}
}

func TestWriteCSV(t *testing.T) {
	results := Results{
		Candidates: []krb.Candidate{
			{
				SamAccountName: "testuser",
				Type:           "ASREP",
				Score:          85,
				Reasons:        []string{"DoesNotRequirePreAuth", "Severity: High"},
				SPNs:           []string{},
				ExportHashPath: "",
			},
			{
				SamAccountName: "sqlsvc",
				Type:           "KERBEROAST",
				Score:          70,
				Reasons:        []string{"Has SPN", "Severity: Medium"},
				SPNs:           []string{"MSSQLSvc/sql.local"},
				ExportHashPath: "/path/to/hash",
			},
		},
	}

	tmpFile := filepath.Join(t.TempDir(), "test.csv")

	err := WriteCSV(tmpFile, results)
	if err != nil {
		t.Fatalf("WriteCSV failed: %v", err)
	}

	// Verify file exists
	if _, err := os.Stat(tmpFile); err != nil {
		t.Fatalf("Output CSV file not created: %v", err)
	}

	// Read and verify content
	content, err := os.ReadFile(tmpFile)
	if err != nil {
		t.Fatalf("Failed to read CSV file: %v", err)
	}

	contentStr := string(content)
	if !containsString(contentStr, "SamAccountName") {
		t.Error("CSV should contain header")
	}

	if !containsString(contentStr, "testuser") {
		t.Error("CSV should contain testuser")
	}

	if !containsString(contentStr, "sqlsvc") {
		t.Error("CSV should contain sqlsvc")
	}
}

func TestExtractSeverity(t *testing.T) {
	testCases := []struct {
		reasons  []string
		expected string
	}{
		{[]string{"DoesNotRequirePreAuth", "Severity: High"}, "High"},
		{[]string{"Has SPN", "Severity: Medium"}, "Medium"},
		{[]string{"DoesNotRequirePreAuth", "Severity: Low"}, "Low"},
		{[]string{"DoesNotRequirePreAuth"}, "Unknown"},
	}

	for _, tc := range testCases {
		result := extractSeverity(tc.reasons)
		if result != tc.expected {
			t.Errorf("For reasons %v, expected %s, got %s", tc.reasons, tc.expected, result)
		}
	}
}

func containsString(s, substr string) bool {
	return len(s) >= len(substr) && strings.Contains(s, substr)
}
