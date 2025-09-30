package advanced

import (
	"testing"
)

func TestNewKerberosRelayEngine(t *testing.T) {
	engine := NewKerberosRelayEngine("test.local", "HTTP/test.local")
	
	if engine == nil {
		t.Fatal("KerberosRelayEngine should not be nil")
	}
	
	if engine.Domain != "test.local" {
		t.Error("Domain should be set correctly")
	}
	
	if engine.TargetSPN != "HTTP/test.local" {
		t.Error("TargetSPN should be set correctly")
	}
	
	if engine.RelayPort != 88 {
		t.Error("RelayPort should default to 88")
	}
	
	if engine.IsListening {
		t.Error("IsListening should be false initially")
	}
	
	if len(engine.CapturedTickets) != 0 {
		t.Error("CapturedTickets should be empty initially")
	}
}

func TestCapturedTicket(t *testing.T) {
	ticket := &CapturedTicket{
		Username:       "testuser",
		Domain:         "test.local",
		SPN:            "HTTP/test.local",
		TicketData:     []byte("testdata"),
		SourceIP:       "192.168.1.1",
		EncryptionType: 18,
	}
	
	if ticket.Username != "testuser" {
		t.Error("Username should be set correctly")
	}
	
	if ticket.Domain != "test.local" {
		t.Error("Domain should be set correctly")
	}
	
	if ticket.SPN != "HTTP/test.local" {
		t.Error("SPN should be set correctly")
	}
	
	if len(ticket.TicketData) != 8 {
		t.Error("TicketData should be set correctly")
	}
	
	if ticket.SourceIP != "192.168.1.1" {
		t.Error("SourceIP should be set correctly")
	}
	
	if ticket.EncryptionType != 18 {
		t.Error("EncryptionType should be set correctly")
	}
}

func TestKerberosRelayEngineStopRelayServer(t *testing.T) {
	engine := NewKerberosRelayEngine("test.local", "HTTP/test.local")
	
	// Test stopping when not listening
	engine.StopRelayServer()
	// StopRelayServer doesn't return an error
}

func TestKerberosRelayEngineCapturedTickets(t *testing.T) {
	engine := NewKerberosRelayEngine("test.local", "HTTP/test.local")
	
	if engine.CapturedTickets == nil {
		t.Error("CapturedTickets should not be nil")
	}
	
	if len(engine.CapturedTickets) != 0 {
		t.Error("CapturedTickets should be empty initially")
	}
}

func TestKerberosRelayEngineCapturedTicketsManipulation(t *testing.T) {
	engine := NewKerberosRelayEngine("test.local", "HTTP/test.local")
	
	// Add a dummy ticket
	engine.CapturedTickets = append(engine.CapturedTickets, &CapturedTicket{
		Username: "testuser",
		Domain:   "test.local",
		SPN:      "HTTP/test.local",
	})
	
	if len(engine.CapturedTickets) != 1 {
		t.Error("Should have 1 captured ticket")
	}
	
	// Clear tickets manually
	engine.CapturedTickets = []*CapturedTicket{}
	
	if len(engine.CapturedTickets) != 0 {
		t.Error("CapturedTickets should be empty after clearing")
	}
}
