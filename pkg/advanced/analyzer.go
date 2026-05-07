package advanced

import (
	"fmt"
	"log"
	"strings"

	"github.com/thechosenone-shall-prevail/cold-relay/pkg/krb"
)

// AdvancedAnalyzer provides access to all advanced Kerberos analysis features
type AdvancedAnalyzer struct {
	Client        *krb.LDAPClient
	AuditMode     bool
	DangerousMode bool
	Target        string
	Username      string
	Password      string
	Domain        string
	Results       map[string]interface{}
}

// NewAdvancedAnalyzer creates a new advanced analyzer
func NewAdvancedAnalyzer(client *krb.LDAPClient, auditMode, dangerousMode bool, target, user, pass, domain string) *AdvancedAnalyzer {
	return &AdvancedAnalyzer{
		Client:        client,
		AuditMode:     auditMode,
		DangerousMode: dangerousMode,
		Target:        target,
		Username:      user,
		Password:      pass,
		Domain:        domain,
		Results:       make(map[string]interface{}),
	}
}

// RunTimeroastingAnalysis runs timeroasting analysis
func (aa *AdvancedAnalyzer) RunTimeroastingAnalysis(kirbiPath string, spns []string) error {
	log.Printf("[*] Starting Timeroasting analysis...")

	analyzer := NewTimeroastAnalyzer(true, true, "")

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
	if aa.Results == nil {
		aa.Results = make(map[string]interface{})
	}
	aa.Results["rbcd"] = report

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
	if aa.Results == nil {
		aa.Results = make(map[string]interface{})
	}
	aa.Results["s4u"] = report

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

	if aa.Results == nil {
		aa.Results = make(map[string]interface{})
	}
	aa.Results["pkinit"] = results

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
	if aa.Results == nil {
		aa.Results = make(map[string]interface{})
	}
	aa.Results["dcsync"] = report

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
	return nil
}

// RunLoggingAnalysis runs logging and detection analysis
func (aa *AdvancedAnalyzer) RunLoggingAnalysis() error {
	log.Printf("[*] Starting logging and detection analysis...")

	analyzer := NewLoggingAnalyzer()

	// Generate Sigma rules
	rules := analyzer.GenerateSigmaRules()
	log.Printf("[+] Generated %d Sigma detection rules", len(rules))

	// Export formats (skipped in Deep Dive mode)
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

// RunPasswordPolicyAnalysis runs password policy analysis
func (aa *AdvancedAnalyzer) RunPasswordPolicyAnalysis() error {
	log.Printf("[*] Starting password policy analysis...")

	analyzer := NewPasswordPolicyAnalyzer(aa.Client, aa.AuditMode)

	// Enumerate password policies
	results, err := analyzer.EnumeratePasswordPolicies()
	if err != nil {
		return fmt.Errorf("password policy enumeration failed: %v", err)
	}

	log.Printf("[+] Found %d password policies", len(results))

	// Generate report
	report := analyzer.GeneratePasswordPolicyReport(results)
	log.Printf("[+] Password policy report generated: %d total, %d high risk, %d medium risk",
		report["total_policies"], report["high_risk_count"], report["medium_risk_count"])

	if aa.Results == nil {
		aa.Results = make(map[string]interface{})
	}
	aa.Results["password_policies"] = report

	return nil
}

// RunLDAPConfigAnalysis runs LDAP configuration analysis
func (aa *AdvancedAnalyzer) RunLDAPConfigAnalysis() error {
	log.Printf("[*] Starting LDAP configuration analysis...")

	analyzer := NewLDAPConfigAnalyzer(aa.Client, aa.AuditMode)

	// Enumerate LDAP misconfigurations
	results, err := analyzer.EnumerateLDAPMisconfigurations()
	if err != nil {
		return fmt.Errorf("LDAP configuration analysis failed: %v", err)
	}

	log.Printf("[+] Completed %d LDAP configuration checks", len(results))

	// Generate report
	report := analyzer.GenerateLDAPConfigReport(results)
	log.Printf("[+] LDAP configuration report generated: %d total, %d vulnerable, %d secure",
		report["total_checks"], report["vulnerable_count"], report["secure_count"])

	if aa.Results == nil {
		aa.Results = make(map[string]interface{})
	}
	aa.Results["ldap_config"] = report

	return nil
}

// RunUserAttributeAnalysis runs user attribute flags analysis
func (aa *AdvancedAnalyzer) RunUserAttributeAnalysis() error {
	log.Printf("[*] Starting user attribute analysis...")

	analyzer := NewUserAttributeAnalyzer(aa.Client, aa.AuditMode)

	// Enumerate user attributes
	results, err := analyzer.EnumerateUserAttributes()
	if err != nil {
		return fmt.Errorf("user attribute enumeration failed: %v", err)
	}

	log.Printf("[+] Analyzed %d user objects for attribute flags", len(results))

	// Detect abuse patterns
	patterns := analyzer.DetectAttributeAbuse(results)
	if len(patterns) > 0 {
		log.Printf("[+] Detected user attribute abuse patterns:")
		for _, pattern := range patterns {
			log.Printf("   - %s", pattern)
		}
	}

	// Generate report
	report := analyzer.GenerateUserAttributeReport(results)
	log.Printf("[+] User attribute report generated: %d total, %d password not required, %d password never expires, %d SID history",
		report["total_users_analyzed"], report["password_not_required_count"], report["password_never_expires_count"], report["sid_history_count"])

	if aa.Results == nil {
		aa.Results = make(map[string]interface{})
	}
	aa.Results["user_attributes"] = report

	return nil
}

// RunShadowCredentialsAnalysis runs shadow credentials (Key Trust AD mapping) analysis
func (aa *AdvancedAnalyzer) RunShadowCredentialsAnalysis() error {
	log.Printf("[*] Starting shadow credentials analysis...")

	analyzer := NewShadowCredentialsAnalyzer(aa.Client, aa.AuditMode)

	// Enumerate shadow credentials
	results, err := analyzer.EnumerateShadowCredentials()
	if err != nil {
		return fmt.Errorf("shadow credentials enumeration failed: %v", err)
	}

	log.Printf("[+] Found %d objects with shadow credentials", len(results))

	// Detect abuse patterns
	patterns := analyzer.DetectShadowCredentialAbuse(results)
	if len(patterns) > 0 {
		log.Printf("[+] Detected shadow credential abuse patterns:")
		for _, pattern := range patterns {
			log.Printf("   - %s", pattern)
		}
	}

	// Generate report
	report := analyzer.GenerateShadowCredentialsReport(results)
	log.Printf("[+] Shadow credentials report generated: %d total, %d critical, %d high",
		report["total_shadow_credentials"], report["critical_risk_count"], report["high_risk_count"])

	if aa.Results == nil {
		aa.Results = make(map[string]interface{})
	}
	aa.Results["shadow_credentials"] = report

	return nil
}

// RunSMBAnalysis runs SMB share enumeration and GPP scanning
func (aa *AdvancedAnalyzer) RunSMBAnalysis() error {
	log.Printf("[*] Starting SMB and GPP analysis...")

	analyzer := NewSMBAnalyzer(aa.Target, aa.Username, aa.Password, aa.Domain)

	// Enumerate shares
	shares, err := analyzer.EnumerateShares()
	if err != nil {
		log.Printf("[!] SMB share enumeration failed: %v", err)
	} else {
		log.Printf("[+] Enumerated %d SMB shares:", len(shares))
		for _, share := range shares {
			log.Printf("   - %s", share)
		}
		aa.Results["shares"] = shares

		// Check for Pwned status
		if admin, _ := analyzer.CheckAdminAccess(); admin {
			log.Printf("%s[+] SMB [Pwned!] - Administrative access detected%s", "\033[1;32m", "\033[0m")
			aa.Results["pwned"] = true
		}

		// Context Intelligence: Deep File Hunt on juicy shares
		juicyShares := []string{"logs", "backup", "it", "hr", "users", "shared", "it_admin", "software"}
		var allFindings []FileFinding
		for _, share := range shares {
			lowerShare := strings.ToLower(share)
			isJuicy := false
			for _, j := range juicyShares {
				if strings.Contains(lowerShare, j) {
					isJuicy = true
					break
				}
			}

			if isJuicy {
				log.Printf("[*] Juicy share detected: %s. Starting deep file hunt...", share)
				findings, err := analyzer.DeepFileHunt(share)
				if err == nil && len(findings) > 0 {
					log.Printf("[+] Found %d sensitive file(s) in %s!", len(findings), share)
					allFindings = append(allFindings, findings...)
				}
			}
		}
		if len(allFindings) > 0 {
			aa.Results["sensitive_files"] = allFindings
		}
	}

	// Scan for GPP passwords
	gppResults, err := analyzer.ScanGPP()
	if err != nil {
		log.Printf("[!] GPP scanning failed: %v", err)
	} else if len(gppResults) > 0 {
		log.Printf("[+] Found %d GPP password(s) in SYSVOL!", len(gppResults))
		aa.Results["gpp"] = gppResults
	}

	return nil
}

// RunFullAnalysis runs all advanced analysis modules
func (aa *AdvancedAnalyzer) RunFullAnalysis() error {
	log.Printf("[*] Starting full advanced Kerberos analysis...")

	// Run all analysis modules
	analyses := []struct {
		name string
		fn   func() error
	}{
		{"smb", aa.RunSMBAnalysis},
		{"trust", aa.RunTrustAnalysis},
		{"dns", aa.RunDNSAnalysis},
		{"laps", aa.RunLAPSAnalysis},
		{"gpo", aa.RunGPOAnalysis},
		{"sessions", aa.RunSessionAnalysis},
		{"acl", aa.RunACLAnalysis},
		{"user_attributes", aa.RunUserAttributeAnalysis},
		{"shadow_credentials", aa.RunShadowCredentialsAnalysis},
		{"password_policy", aa.RunPasswordPolicyAnalysis},
		{"ldap_config", aa.RunLDAPConfigAnalysis},
		{"rbcd", aa.RunRBCDAnalysis},
		{"s4u", aa.RunS4UAnalysis},
		{"pkinit", aa.RunPKINITAnalysis},
		{"dcsync", aa.RunDCSyncAnalysis},
		{"logging", aa.RunLoggingAnalysis},
	}

	for _, a := range analyses {
		if err := a.fn(); err != nil {
			log.Printf("[x] %s analysis failed: %v", a.name, err)
		}
	}

	if aa.Results == nil {
		aa.Results = make(map[string]interface{})
	}
	deleg := make(map[string]interface{})
	if v, ok := aa.Results["rbcd"]; ok {
		deleg["rbcd"] = v
	}
	if v, ok := aa.Results["s4u"]; ok {
		deleg["s4u"] = v
	}
	if len(deleg) > 0 {
		aa.Results["delegation"] = deleg
	}

	log.Printf("[+] Full advanced analysis completed")
	return nil
}
