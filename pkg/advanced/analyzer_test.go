package advanced

import (
	"testing"
	"github.com/thechosenone-shall-prevail/KERB-SLEUTH/pkg/krb"
)

func TestNewAdvancedAnalyzer(t *testing.T) {
	client := &krb.LDAPClient{}
	analyzer := NewAdvancedAnalyzer(client, true, false, "test_output")
	
	if analyzer == nil {
		t.Fatal("AdvancedAnalyzer should not be nil")
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
	
	if analyzer.OutputDir != "test_output" {
		t.Error("OutputDir should be set correctly")
	}
}

func TestAdvancedAnalyzerRunTimeroastingAnalysis(t *testing.T) {
	client := &krb.LDAPClient{}
	analyzer := NewAdvancedAnalyzer(client, true, false, "test_output")
	
	// Test with empty kirbi path and empty SPNs
	err := analyzer.RunTimeroastingAnalysis("", []string{})
	if err != nil {
		t.Errorf("RunTimeroastingAnalysis should not fail with empty inputs: %v", err)
	}
}

func TestAdvancedAnalyzerRunDCSyncAnalysis(t *testing.T) {
	client := &krb.LDAPClient{}
	analyzer := NewAdvancedAnalyzer(client, true, false, "test_output")
	
	err := analyzer.RunDCSyncAnalysis()
	if err != nil {
		t.Errorf("RunDCSyncAnalysis should not fail: %v", err)
	}
}

func TestAdvancedAnalyzerRunRBCDAnalysis(t *testing.T) {
	client := &krb.LDAPClient{}
	analyzer := NewAdvancedAnalyzer(client, true, false, "test_output")
	
	err := analyzer.RunRBCDAnalysis()
	if err != nil {
		t.Errorf("RunRBCDAnalysis should not fail: %v", err)
	}
}

func TestAdvancedAnalyzerRunS4UAnalysis(t *testing.T) {
	client := &krb.LDAPClient{}
	analyzer := NewAdvancedAnalyzer(client, true, false, "test_output")
	
	err := analyzer.RunS4UAnalysis()
	if err != nil {
		t.Errorf("RunS4UAnalysis should not fail: %v", err)
	}
}

func TestAdvancedAnalyzerRunPKINITAnalysis(t *testing.T) {
	client := &krb.LDAPClient{}
	analyzer := NewAdvancedAnalyzer(client, true, false, "test_output")
	
	err := analyzer.RunPKINITAnalysis()
	if err != nil {
		t.Errorf("RunPKINITAnalysis should not fail: %v", err)
	}
}

func TestAdvancedAnalyzerRunTicketLifetimeAnalysis(t *testing.T) {
	client := &krb.LDAPClient{}
	analyzer := NewAdvancedAnalyzer(client, true, false, "test_output")
	
	// Test with empty ticket data
	ticketData := []map[string]interface{}{}
	err := analyzer.RunTicketLifetimeAnalysis(ticketData)
	if err != nil {
		t.Errorf("RunTicketLifetimeAnalysis should not fail: %v", err)
	}
}

func TestAdvancedAnalyzerRunLoggingAnalysis(t *testing.T) {
	client := &krb.LDAPClient{}
	analyzer := NewAdvancedAnalyzer(client, true, false, "test_output")
	
	err := analyzer.RunLoggingAnalysis()
	if err != nil {
		t.Errorf("RunLoggingAnalysis should not fail: %v", err)
	}
}
