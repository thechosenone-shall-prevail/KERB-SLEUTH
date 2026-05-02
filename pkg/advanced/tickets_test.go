package advanced

import (
	"testing"
	"time"
	"github.com/thechosenone-shall-prevail/KERB-SLEUTH/pkg/krb"
)

func TestNewTicketAnalyzer(t *testing.T) {
	client := &krb.LDAPClient{}
	analyzer := NewTicketAnalyzer(client, true, false)
	
	if analyzer == nil {
		t.Fatal("TicketAnalyzer should not be nil")
	}
	
	if analyzer.Client != client {
		t.Error("Client should be set correctly")
	}
	
	if !analyzer.AuditMode {
		t.Error("AuditMode should be true")
	}
	
	if analyzer.DangerousMode {
		t.Error("DangerousMode should be false")
	}
}

func TestAnalyzeTicket(t *testing.T) {
	client := &krb.LDAPClient{}
	analyzer := NewTicketAnalyzer(client, true, false)
	
	// Test with empty ticket data
	ticketData := []byte{}
	result, err := analyzer.AnalyzeTicket(ticketData, "Golden")
	
	if err == nil {
		t.Error("AnalyzeTicket should fail with empty ticket data")
	}
	
	if result != nil {
		t.Error("Result should be nil when error occurs")
	}
}

func TestAnalyzeTicketWithEmptyData(t *testing.T) {
	client := &krb.LDAPClient{}
	analyzer := NewTicketAnalyzer(client, true, false)
	
	// Test with empty ticket data
	ticketData := []byte{}
	result, err := analyzer.AnalyzeTicket(ticketData, "Golden")
	
	if err == nil {
		t.Error("AnalyzeTicket should fail with empty ticket data")
	}
	
	if result != nil {
		t.Error("Result should be nil when error occurs")
	}
}

func TestTicketAnalyzerInitialization(t *testing.T) {
	client := &krb.LDAPClient{}
	analyzer := NewTicketAnalyzer(client, true, false)
	
	if analyzer == nil {
		t.Fatal("TicketAnalyzer should not be nil")
	}
	
	if analyzer.Client != client {
		t.Error("Client should be set correctly")
	}
	
	if !analyzer.AuditMode {
		t.Error("AuditMode should be true")
	}
	
	if analyzer.DangerousMode {
		t.Error("DangerousMode should be false")
	}
}

func TestTicketResultValidation(t *testing.T) {
	result := &TicketResult{
		TicketType:        "Golden",
		Username:          "testuser",
		Domain:            "test.local",
		ServiceAccount:    "",
		EncryptionType:    18,
		StartTime:         time.Now(),
		EndTime:           time.Now().Add(10 * time.Hour),
		RenewTill:         time.Now().Add(7 * 24 * time.Hour),
		Flags:             []string{"forwardable", "renewable"},
		IsForged:          false,
		ForgeryIndicators: []string{},
		Hash:              "testhash",
		Metadata:          map[string]interface{}{},
		RiskLevel:         "Medium",
	}
	
	if result.TicketType != "Golden" {
		t.Error("TicketType should be set correctly")
	}
	
	if result.Username != "testuser" {
		t.Error("Username should be set correctly")
	}
	
	if result.Domain != "test.local" {
		t.Error("Domain should be set correctly")
	}
	
	if result.EncryptionType != 18 {
		t.Error("EncryptionType should be set correctly")
	}
	
	if result.RiskLevel != "Medium" {
		t.Error("RiskLevel should be set correctly")
	}
}
