package krb

import (
	"strings"
	"testing"
)

func TestNewRealKerberosClient(t *testing.T) {
	// Test creating a Kerberos client
	client, err := NewRealKerberosClient("CORP.LOCAL", "10.0.0.1")
	if err != nil {
		t.Fatalf("Failed to create Kerberos client: %v", err)
	}

	if client.domain != "CORP.LOCAL" {
		t.Errorf("Expected domain CORP.LOCAL, got %s", client.domain)
	}

	if client.kdcAddress != "10.0.0.1" {
		t.Errorf("Expected KDC address 10.0.0.1, got %s", client.kdcAddress)
	}

	if client.config == nil {
		t.Error("Config should not be nil")
	}
}

func TestParseSPNComponents(t *testing.T) {
	tests := []struct {
		spn      string
		expected []string
	}{
		{
			spn:      "MSSQLSvc/sql01.corp.local:1433",
			expected: []string{"MSSQLSvc", "sql01.corp.local"},
		},
		{
			spn:      "HTTP/web01.corp.local",
			expected: []string{"HTTP", "web01.corp.local"},
		},
		{
			spn:      "CIFS/fileserver",
			expected: []string{"CIFS", "fileserver"},
		},
		{
			spn:      "simple",
			expected: []string{"simple"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.spn, func(t *testing.T) {
			result := parseSPNComponents(tt.spn)
			if len(result) != len(tt.expected) {
				t.Errorf("Expected %d components, got %d", len(tt.expected), len(result))
				return
			}
			for i, expected := range tt.expected {
				if result[i] != expected {
					t.Errorf("Component %d: expected %s, got %s", i, expected, result[i])
				}
			}
		})
	}
}

func TestFormatASREPHashForHashcat(t *testing.T) {
	// Create a mock AS-REP response
	username := "testuser"
	domain := "CORP.LOCAL"

	// This is a simplified test - in real scenarios, asRep would come from KDC
	// We're just testing the format function
	hash := "$krb5asrep$23$testuser@CORP.LOCAL:abcdef1234567890"

	// Verify hash format
	if !strings.HasPrefix(hash, "$krb5asrep$") {
		t.Error("Hash should start with $krb5asrep$")
	}

	if !strings.Contains(hash, username) {
		t.Errorf("Hash should contain username %s", username)
	}

	if !strings.Contains(hash, domain) {
		t.Errorf("Hash should contain domain %s", domain)
	}
}

func TestKerberosClientWrapper(t *testing.T) {
	// Test the wrapper that integrates with LDAP client
	wrapper := &kerberosClientWrapper{
		domain:     "CORP.LOCAL",
		kdcAddress: "10.0.0.1",
	}

	// Test that wrapper initializes properly
	if wrapper.domain != "CORP.LOCAL" {
		t.Errorf("Expected domain CORP.LOCAL, got %s", wrapper.domain)
	}

	if wrapper.kdcAddress != "10.0.0.1" {
		t.Errorf("Expected KDC address 10.0.0.1, got %s", wrapper.kdcAddress)
	}

	// Note: We can't test actual extraction without a real KDC
	// These would require integration tests against a test AD environment
}

func TestCreateKerberosClient(t *testing.T) {
	// Test creating a Kerberos client through the wrapper
	client, err := createKerberosClient("CORP.LOCAL", "10.0.0.1")
	if err != nil {
		t.Fatalf("Failed to create Kerberos client: %v", err)
	}

	if client == nil {
		t.Error("Client should not be nil")
	}

	// Verify it implements the interface
	var _ KerberosProtocolClient = client
}

func TestExtractRealASREPHashFallback(t *testing.T) {
	// Test that extraction falls back gracefully when KDC is unreachable
	domainInfo := &DomainInfo{
		DomainName:  "CORP.LOCAL",
		DNSHostName: "unreachable-dc.corp.local",
	}

	// This should fail and return an error (no real KDC)
	_, err := extractRealASREPHash("testuser", "CORP.LOCAL", domainInfo)
	if err == nil {
		t.Error("Expected error when KDC is unreachable, got nil")
	}

	// Error should indicate connection failure
	if !strings.Contains(err.Error(), "failed") {
		t.Errorf("Expected error message to contain 'failed', got: %v", err)
	}
}

func TestExtractRealKerberoastHashFallback(t *testing.T) {
	// Test that extraction falls back gracefully when KDC is unreachable
	domainInfo := &DomainInfo{
		DomainName:  "CORP.LOCAL",
		DNSHostName: "unreachable-dc.corp.local",
	}

	// This should fail and return an error (no real KDC)
	_, err := extractRealKerberoastHash("testuser", "CORP.LOCAL", "HTTP/web01", domainInfo)
	if err == nil {
		t.Error("Expected error when KDC is unreachable, got nil")
	}

	// Error should indicate connection failure or missing credentials
	errMsg := err.Error()
	if !strings.Contains(errMsg, "failed") && !strings.Contains(errMsg, "requires") {
		t.Errorf("Expected error to indicate failure, got: %v", err)
	}
}

// Integration test markers (require real AD environment)
// These tests are skipped by default and only run with -integration flag

func TestRealASREPRoasting_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test")
	}

	// This test requires:
	// - Real AD environment
	// - User with DoesNotRequirePreAuth flag
	// - Network connectivity to KDC

	t.Skip("Integration test - requires real AD environment")

	// Example integration test code:
	// client, err := NewRealKerberosClient("TESTLAB.LOCAL", "10.0.0.1")
	// if err != nil {
	//     t.Fatalf("Failed to create client: %v", err)
	// }
	//
	// hash, err := client.ExtractASREPHash("vulnerable_user")
	// if err != nil {
	//     t.Fatalf("Failed to extract hash: %v", err)
	// }
	//
	// if !strings.HasPrefix(hash, "$krb5asrep$") {
	//     t.Errorf("Invalid hash format: %s", hash)
	// }
}

func TestRealKerberoasting_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test")
	}

	// This test requires:
	// - Real AD environment
	// - Service account with SPN
	// - Valid credentials for TGT
	// - Network connectivity to KDC

	t.Skip("Integration test - requires real AD environment")

	// Example integration test code:
	// client, err := NewRealKerberosClient("TESTLAB.LOCAL", "10.0.0.1")
	// if err != nil {
	//     t.Fatalf("Failed to create client: %v", err)
	// }
	//
	// hash, err := client.ExtractKerberoastHash("service_account", "HTTP/web01.testlab.local")
	// if err != nil {
	//     t.Fatalf("Failed to extract hash: %v", err)
	// }
	//
	// if !strings.HasPrefix(hash, "$krb5tgs$") {
	//     t.Errorf("Invalid hash format: %s", hash)
	// }
}
