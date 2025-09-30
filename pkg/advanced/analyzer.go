package advanced

import (
	"fmt"
	"log"
	"os"

	"github.com/thechosenone-shall-prevail/KERB-SLEUTH/pkg/krb"
)

// AdvancedAnalyzer provides access to all advanced Kerberos analysis features
type AdvancedAnalyzer struct {
	Client        *krb.LDAPClient
	AuditMode     bool
	DangerousMode bool
	OutputDir     string
}

// NewAdvancedAnalyzer creates a new advanced analyzer
func NewAdvancedAnalyzer(client *krb.LDAPClient, auditMode, dangerousMode bool, outputDir string) *AdvancedAnalyzer {
	// Create output directory
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		log.Printf("[x] Failed to create output directory: %v", err)
	}

	return &AdvancedAnalyzer{
		Client:        client,
		AuditMode:     auditMode,
		DangerousMode: dangerousMode,
		OutputDir:     outputDir,
	}
}

// RunTimeroastingAnalysis runs timeroasting analysis
func (aa *AdvancedAnalyzer) RunTimeroastingAnalysis(kirbiPath string, spns []string) error {
	log.Printf("[*] Starting Timeroasting analysis...")

	analyzer := NewTimeroastAnalyzer(true, true, aa.OutputDir)

	var results []*TimeroastResult

	// Analyze kirbi files if provided
	if kirbiPath != "" {
		kirbiResults, err := analyzer.AnalyzeTicketCache(kirbiPath)
		if err != nil {
			log.Printf("[x] Kirbi analysis failed: %v", err)
		} else {
			results = append(results, kirbiResults...)
		}
	}

	// Request tickets for SPNs if provided
	if len(spns) > 0 {
		spnResults, err := analyzer.RequestTicketsUnderSPN(aa.Client, spns)
		if err != nil {
			log.Printf("[x] SPN ticket requests failed: %v", err)
		} else {
			results = append(results, spnResults...)
		}
	}

	// Detect patterns
	patterns := analyzer.DetectTimeroastingPatterns(results)
	if len(patterns) > 0 {
		log.Printf("[+] Detected timeroasting patterns:")
		for _, pattern := range patterns {
			log.Printf("   - %s", pattern)
		}
	}

	// Export results
	if len(results) > 0 {
		return analyzer.ExportTimeroastHashes(results)
	}

	return nil
}

// RunRBCDAnalysis runs RBCD enumeration and analysis
func (aa *AdvancedAnalyzer) RunRBCDAnalysis() error {
	log.Printf("[*] Starting RBCD analysis...")

	analyzer := NewRBCDAnalyzer(aa.Client, aa.AuditMode)

	// Enumerate RBCD targets
	results, err := analyzer.EnumerateRBCDTargets()
	if err != nil {
		return fmt.Errorf("RBCD enumeration failed: %v", err)
	}

	log.Printf("[+] Found %d RBCD targets", len(results))

	// Detect suspicious values
	suspicious := analyzer.DetectSuspiciousRBCDValues(results)
	if len(suspicious) > 0 {
		log.Printf("[+] Detected suspicious RBCD configurations:")
		for _, s := range suspicious {
			log.Printf("   - %s", s)
		}
	}

	// Generate report
	report := analyzer.GenerateExploitationReport(results)
	log.Printf("[+] RBCD analysis report generated: %d targets analyzed, %d high-risk", len(results), len(report["high_risk_targets"].([]*RBCDResult)))

	return nil
}

// RunS4UAnalysis runs S4U delegation analysis
func (aa *AdvancedAnalyzer) RunS4UAnalysis() error {
	log.Printf("[*] Starting S4U analysis...")

	analyzer := NewS4UAnalyzer(aa.Client, aa.AuditMode)

	// Enumerate S4U delegation
	results, err := analyzer.EnumerateS4UDelegation()
	if err != nil {
		return fmt.Errorf("S4U enumeration failed: %v", err)
	}

	log.Printf("[+] Found %d S4U delegation configurations", len(results))

	// Detect abuse patterns
	patterns := analyzer.DetectS4UAbusePatterns(results)
	if len(patterns) > 0 {
		log.Printf("[+] Detected S4U abuse patterns:")
		for _, pattern := range patterns {
			log.Printf("   - %s", pattern)
		}
	}

	// Generate report
	report := analyzer.GenerateS4UReport(results)
	log.Printf("[+] S4U analysis report generated: %v", report)

	return nil
}

// RunOverpassAnalysis runs Overpass-the-Hash analysis
func (aa *AdvancedAnalyzer) RunOverpassAnalysis(hashes map[string]string) error {
	log.Printf("[*] Starting Overpass-the-Hash analysis...")

	analyzer := NewOverpassAnalyzer(aa.Client, aa.AuditMode)

	// Process hashes
	results, err := analyzer.BatchProcessHashes(hashes)
	if err != nil {
		return fmt.Errorf("Overpass analysis failed: %v", err)
	}

	log.Printf("[+] Processed %d NTLM hashes", len(results))

	// Detect patterns
	patterns := analyzer.DetectOverpassPatterns(results)
	if len(patterns) > 0 {
		log.Printf("[+] Detected Overpass-the-Hash patterns:")
		for _, pattern := range patterns {
			log.Printf("   - %s", pattern)
		}
	}

	// Export results
	if len(results) > 0 {
		return analyzer.ExportOverpassHashes(results, aa.OutputDir)
	}

	return nil
}

// RunTicketAnalysis runs Silver/Golden ticket analysis
func (aa *AdvancedAnalyzer) RunTicketAnalysis(ticketData []byte, ticketType string) error {
	log.Printf("[*] Starting Silver/Golden ticket analysis...")

	analyzer := NewTicketAnalyzer(aa.Client, aa.AuditMode, aa.DangerousMode)

	// Analyze ticket
	result, err := analyzer.AnalyzeTicket(ticketData, ticketType)
	if err != nil {
		return fmt.Errorf("ticket analysis failed: %v", err)
	}

	log.Printf("[+] Ticket analysis completed: %s ticket, Risk: %s", result.TicketType, result.RiskLevel)

	if result.IsForged {
		log.Printf("[+] FORGED TICKET DETECTED!")
		for _, indicator := range result.ForgeryIndicators {
			log.Printf("   - %s", indicator)
		}
	}

	// Export results if in dangerous mode
	if aa.DangerousMode && result.Hash != "" {
		results := []*TicketResult{result}
		return analyzer.ExportTicketHashes(results, aa.OutputDir)
	}

	return nil
}

// RunPKINITAnalysis runs PKINIT/AD CS analysis
func (aa *AdvancedAnalyzer) RunPKINITAnalysis() error {
	log.Printf("[*] Starting PKINIT/AD CS analysis...")

	analyzer := NewPKINITAnalyzer(aa.Client, aa.AuditMode)

	// Enumerate AD CS templates
	results, err := analyzer.EnumerateADCS()
	if err != nil {
		return fmt.Errorf("PKINIT enumeration failed: %v", err)
	}

	log.Printf("[+] Found %d certificate templates", len(results))

	// Detect abuse patterns
	patterns := analyzer.DetectPKINITAbuse(results)
	if len(patterns) > 0 {
		log.Printf("[+] Detected PKINIT abuse patterns:")
		for _, pattern := range patterns {
			log.Printf("   - %s", pattern)
		}
	}

	return nil
}

// RunDCSyncAnalysis runs DCSync enumeration analysis
func (aa *AdvancedAnalyzer) RunDCSyncAnalysis() error {
	log.Printf("[*] Starting DCSync analysis...")

	analyzer := NewDCSyncAnalyzer(aa.Client, aa.AuditMode)

	// Enumerate replication rights
	results, err := analyzer.EnumerateReplicationRights()
	if err != nil {
		return fmt.Errorf("DCSync enumeration failed: %v", err)
	}

	log.Printf("[+] Found %d accounts with replication rights", len(results))

	// Detect abuse patterns
	patterns := analyzer.DetectDCSyncAbuse(results)
	if len(patterns) > 0 {
		log.Printf("[+] Detected DCSync abuse patterns:")
		for _, pattern := range patterns {
			log.Printf("   - %s", pattern)
		}
	}

	// Generate report
	report := analyzer.GenerateDCSyncReport(results)
	log.Printf("[+] DCSync analysis report generated: %v", report)

	return nil
}

// RunTicketLifetimeAnalysis runs ticket lifetime analysis
func (aa *AdvancedAnalyzer) RunTicketLifetimeAnalysis(ticketData []map[string]interface{}) error {
	log.Printf("[*] Starting ticket lifetime analysis...")

	analyzer := NewTicketLifetimeAnalyzer()

	// Analyze each ticket
	for _, data := range ticketData {
		_, err := analyzer.AnalyzeTicketLifetime(data)
		if err != nil {
			log.Printf("[x] Failed to analyze ticket lifetime: %v", err)
			continue
		}
	}

	// Generate timeline
	timeline := analyzer.GenerateTimeline()
	log.Printf("[+] Generated timeline with %d tickets", timeline["total_tickets"])

	// Generate heatmap
	heatmap := analyzer.GenerateHeatmap()
	log.Printf("[+] Generated heatmap with lifetime ranges: %v", heatmap)

	// Export analysis
	return analyzer.ExportAnalysis(aa.OutputDir)
}

// RunLoggingAnalysis runs logging and detection analysis
func (aa *AdvancedAnalyzer) RunLoggingAnalysis() error {
	log.Printf("[*] Starting logging and detection analysis...")

	analyzer := NewLoggingAnalyzer()

	// Generate Sigma rules
	rules := analyzer.GenerateSigmaRules()
	log.Printf("[+] Generated %d Sigma detection rules", len(rules))

	// Export formats
	splunkFile := fmt.Sprintf("%s/splunk_events.json", aa.OutputDir)
	if err := analyzer.ExportSplunkFormat(splunkFile); err != nil {
		log.Printf("[x] Failed to export Splunk format: %v", err)
	}

	iocFile := fmt.Sprintf("%s/iocs.txt", aa.OutputDir)
	if err := analyzer.ExportIOCs(iocFile); err != nil {
		log.Printf("[x] Failed to export IOCs: %v", err)
	}

	return nil
}

// RunPasswordModificationAnalysis runs password modification analysis
func (aa *AdvancedAnalyzer) RunPasswordModificationAnalysis(targetAccount string) error {
	log.Printf("[*] Starting password modification analysis...")

	analyzer := NewPasswordModificationAnalyzer(aa.AuditMode, true) // Always dry run by default

	// Analyze password modification
	result, err := analyzer.AnalyzePasswordModification(targetAccount)
	if err != nil {
		return fmt.Errorf("password modification analysis failed: %v", err)
	}

	log.Printf("[+] Password modification analysis completed for %s", result.TargetAccount)
	log.Printf("   Risk Level: %s", result.RiskLevel)
	log.Printf("   Required ACLs: %d", len(result.RequiredACLs))
	log.Printf("   Required Rights: %d", len(result.RequiredRights))

	// Interactive analysis
	interactive, err := analyzer.WhatWouldIChange(targetAccount)
	if err != nil {
		log.Printf("[x] Interactive analysis failed: %v", err)
	} else {
		log.Printf("[+] Interactive analysis completed: %v", interactive)
	}

	return nil
}

// RunFullAnalysis runs all advanced analysis modules
func (aa *AdvancedAnalyzer) RunFullAnalysis() error {
	log.Printf("[*] Starting full advanced Kerberos analysis...")

	// Run all analysis modules
	analyses := []func() error{
		aa.RunRBCDAnalysis,
		aa.RunS4UAnalysis,
		aa.RunPKINITAnalysis,
		aa.RunDCSyncAnalysis,
		aa.RunLoggingAnalysis,
	}

	for _, analysis := range analyses {
		if err := analysis(); err != nil {
			log.Printf("[x] Analysis failed: %v", err)
		}
	}

	log.Printf("[+] Full advanced analysis completed")
	return nil
}
