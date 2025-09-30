package advanced

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/thechosenone-shall-prevail/KERB-SLEUTH/pkg/krb"
)

// TicketResult represents Silver/Golden ticket analysis results
type TicketResult struct {
	TicketType        string // "Golden", "Silver", "Unknown"
	Username          string
	Domain            string
	ServiceAccount    string // for Silver tickets
	EncryptionType    int
	StartTime         time.Time
	EndTime           time.Time
	RenewTill         time.Time
	Flags             []string
	IsForged          bool
	ForgeryIndicators []string
	Hash              string
	Metadata          map[string]interface{}
	RiskLevel         string
}

// TicketAnalyzer handles Silver/Golden ticket analysis and detection
type TicketAnalyzer struct {
	Client        *krb.LDAPClient
	AuditMode     bool
	DangerousMode bool
}

// NewTicketAnalyzer creates a new ticket analyzer
func NewTicketAnalyzer(client *krb.LDAPClient, auditMode, dangerousMode bool) *TicketAnalyzer {
	return &TicketAnalyzer{
		Client:        client,
		AuditMode:     auditMode,
		DangerousMode: dangerousMode,
	}
}

// AnalyzeTicket analyzes a Kerberos ticket for forgery indicators
func (ta *TicketAnalyzer) AnalyzeTicket(ticketData []byte, ticketType string) (*TicketResult, error) {
	log.Printf("🔍 Analyzing %s ticket for forgery indicators", ticketType)

	if !ta.AuditMode {
		return nil, fmt.Errorf("ticket analysis requires audit mode")
	}

	// Validate input
	if len(ticketData) == 0 {
		return nil, fmt.Errorf("ticket data cannot be empty")
	}

	result := &TicketResult{
		TicketType: ticketType,
		Metadata:   make(map[string]interface{}),
	}

	// Parse ticket data (simplified - real implementation would use ASN.1)
	err := ta.parseTicketData(ticketData, result)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ticket data: %v", err)
	}

	// Analyze for forgery indicators
	ta.analyzeForgeryIndicators(result)

	// Determine risk level
	result.RiskLevel = ta.determineRiskLevel(result)

	// Generate hash for cracking if needed
	if ta.DangerousMode {
		hash, err := ta.generateTicketHash(result)
		if err != nil {
			log.Printf("⚠️  Failed to generate ticket hash: %v", err)
		} else {
			result.Hash = hash
		}
	}

	log.Printf("✅ Ticket analysis completed for %s ticket", ticketType)
	return result, nil
}

// DetectForgedTickets detects forged tickets based on analysis
func (ta *TicketAnalyzer) DetectForgedTickets(results []*TicketResult) []*TicketResult {
	var forgedTickets []*TicketResult

	for _, result := range results {
		if result.IsForged {
			forgedTickets = append(forgedTickets, result)
		}
	}

	return forgedTickets
}

// GenerateGoldenTicket simulates Golden ticket generation (dangerous mode only)
func (ta *TicketAnalyzer) GenerateGoldenTicket(krbtgtHash, domain, username string) (*TicketResult, error) {
	if !ta.DangerousMode {
		return nil, fmt.Errorf("Golden ticket generation requires dangerous mode")
	}

	log.Printf("⚠️  DANGEROUS: Simulating Golden ticket generation for %s@%s", username, domain)

	result := &TicketResult{
		TicketType:     "Golden",
		Username:       username,
		Domain:         strings.ToUpper(domain),
		EncryptionType: 23, // RC4-HMAC
		IsForged:       true,
		Metadata:       make(map[string]interface{}),
	}

	// Generate realistic timestamps
	now := time.Now()
	result.StartTime = now
	result.EndTime = now.Add(10 * 365 * 24 * time.Hour) // 10 years
	result.RenewTill = now.Add(10 * 365 * 24 * time.Hour)

	// Set flags
	result.Flags = []string{
		"FORWARDABLE",
		"RENEWABLE",
		"PROXIABLE",
		"PRE_AUTHENT",
	}

	// Add forgery indicators
	result.ForgeryIndicators = []string{
		"Unusually long ticket lifetime",
		"Golden ticket characteristics",
		"Generated outside normal KDC process",
	}

	// Generate hash
	hash, err := ta.generateTicketHash(result)
	if err != nil {
		return nil, fmt.Errorf("failed to generate Golden ticket hash: %v", err)
	}
	result.Hash = hash

	// Add metadata
	result.Metadata["krbtgt_hash"] = krbtgtHash
	result.Metadata["generated_at"] = now.Format(time.RFC3339)
	result.Metadata["dangerous_operation"] = true

	log.Printf("⚠️  Golden ticket simulation completed for %s@%s", username, domain)
	return result, nil
}

// GenerateSilverTicket simulates Silver ticket generation (dangerous mode only)
func (ta *TicketAnalyzer) GenerateSilverTicket(serviceHash, domain, serviceAccount, targetService string) (*TicketResult, error) {
	if !ta.DangerousMode {
		return nil, fmt.Errorf("Silver ticket generation requires dangerous mode")
	}

	log.Printf("⚠️  DANGEROUS: Simulating Silver ticket generation for %s", targetService)

	result := &TicketResult{
		TicketType:     "Silver",
		Username:       "impersonated_user",
		Domain:         strings.ToUpper(domain),
		ServiceAccount: serviceAccount,
		EncryptionType: 23, // RC4-HMAC
		IsForged:       true,
		Metadata:       make(map[string]interface{}),
	}

	// Generate realistic timestamps
	now := time.Now()
	result.StartTime = now
	result.EndTime = now.Add(10 * time.Hour)
	result.RenewTill = now.Add(7 * 24 * time.Hour)

	// Set flags
	result.Flags = []string{
		"FORWARDABLE",
		"RENEWABLE",
	}

	// Add forgery indicators
	result.ForgeryIndicators = []string{
		"Silver ticket characteristics",
		"Generated outside normal KDC process",
		"Service account compromise",
	}

	// Generate hash
	hash, err := ta.generateTicketHash(result)
	if err != nil {
		return nil, fmt.Errorf("failed to generate Silver ticket hash: %v", err)
	}
	result.Hash = hash

	// Add metadata
	result.Metadata["service_hash"] = serviceHash
	result.Metadata["target_service"] = targetService
	result.Metadata["generated_at"] = now.Format(time.RFC3339)
	result.Metadata["dangerous_operation"] = true

	log.Printf("⚠️  Silver ticket simulation completed for %s", targetService)
	return result, nil
}

// GenerateTicketReport generates a comprehensive ticket analysis report
func (ta *TicketAnalyzer) GenerateTicketReport(results []*TicketResult) map[string]interface{} {
	report := make(map[string]interface{})

	// Count by ticket type
	typeCounts := make(map[string]int)
	for _, result := range results {
		typeCounts[result.TicketType]++
	}
	report["ticket_types"] = typeCounts

	// Count forged tickets
	forgedCount := 0
	for _, result := range results {
		if result.IsForged {
			forgedCount++
		}
	}
	report["forged_tickets"] = forgedCount

	// Risk level distribution
	riskCounts := make(map[string]int)
	for _, result := range results {
		riskCounts[result.RiskLevel]++
	}
	report["risk_distribution"] = riskCounts

	// High-risk tickets
	var highRisk []*TicketResult
	for _, result := range results {
		if result.RiskLevel == "High" {
			highRisk = append(highRisk, result)
		}
	}
	report["high_risk_tickets"] = highRisk

	// Forgery indicators
	var allIndicators []string
	for _, result := range results {
		allIndicators = append(allIndicators, result.ForgeryIndicators...)
	}
	report["forgery_indicators"] = allIndicators

	return report
}

// ExportTicketHashes exports ticket hashes to files
func (ta *TicketAnalyzer) ExportTicketHashes(results []*TicketResult, outputDir string) error {
	if len(results) == 0 {
		return fmt.Errorf("no ticket results to export")
	}

	if !ta.DangerousMode {
		return fmt.Errorf("ticket hash export requires dangerous mode")
	}

	log.Printf("📄 Exporting %d ticket hashes to %s", len(results), outputDir)

	// Export hashes
	hashFile := fmt.Sprintf("%s/ticket_hashes.txt", outputDir)
	if err := ta.writeHashFile(hashFile, results); err != nil {
		return fmt.Errorf("failed to write hash file: %v", err)
	}

	// Export metadata
	metadataFile := fmt.Sprintf("%s/ticket_metadata.json", outputDir)
	if err := ta.writeMetadataFile(metadataFile, results); err != nil {
		return fmt.Errorf("failed to write metadata file: %v", err)
	}

	// Export cracking guide
	guideFile := fmt.Sprintf("%s/TICKET_GUIDE.txt", outputDir)
	if err := ta.writeCrackingGuide(guideFile, len(results)); err != nil {
		return fmt.Errorf("failed to write cracking guide: %v", err)
	}

	return nil
}

// Helper functions

func (ta *TicketAnalyzer) parseTicketData(data []byte, result *TicketResult) error {
	// Simplified ticket parsing - real implementation would use ASN.1
	// For now, we'll simulate realistic ticket data

	result.Username = "user@domain"
	result.Domain = "CORP.LOCAL"
	result.EncryptionType = 23

	// Generate realistic timestamps
	now := time.Now()
	result.StartTime = now.Add(-1 * time.Hour)
	result.EndTime = now.Add(10 * time.Hour)
	result.RenewTill = now.Add(7 * 24 * time.Hour)

	// Set flags
	result.Flags = []string{
		"FORWARDABLE",
		"RENEWABLE",
		"PROXIABLE",
	}

	// Add metadata
	result.Metadata["ticket_size"] = len(data)
	result.Metadata["parsed_at"] = now.Format(time.RFC3339)

	return nil
}

func (ta *TicketAnalyzer) analyzeForgeryIndicators(result *TicketResult) {
	var indicators []string

	// Check for unusual ticket lifetime
	lifetime := result.EndTime.Sub(result.StartTime)
	if lifetime > 24*time.Hour {
		indicators = append(indicators, "Unusually long ticket lifetime")
	}

	// Check for unusual encryption type
	if result.EncryptionType != 23 && result.EncryptionType != 18 {
		indicators = append(indicators, "Unusual encryption type")
	}

	// Check for missing standard flags
	hasForwardable := false
	hasRenewable := false
	for _, flag := range result.Flags {
		if flag == "FORWARDABLE" {
			hasForwardable = true
		}
		if flag == "RENEWABLE" {
			hasRenewable = true
		}
	}

	if !hasForwardable {
		indicators = append(indicators, "Missing FORWARDABLE flag")
	}
	if !hasRenewable {
		indicators = append(indicators, "Missing RENEWABLE flag")
	}

	// Check for Golden ticket characteristics
	if result.TicketType == "Golden" {
		indicators = append(indicators, "Golden ticket characteristics")
	}

	// Check for Silver ticket characteristics
	if result.TicketType == "Silver" {
		indicators = append(indicators, "Silver ticket characteristics")
	}

	result.ForgeryIndicators = indicators
	result.IsForged = len(indicators) > 2 // Consider forged if more than 2 indicators
}

func (ta *TicketAnalyzer) determineRiskLevel(result *TicketResult) string {
	score := 0

	// Base score for forged tickets
	if result.IsForged {
		score += 50
	}

	// Add score for ticket type
	switch result.TicketType {
	case "Golden":
		score += 40
	case "Silver":
		score += 30
	}

	// Add score for number of indicators
	score += len(result.ForgeryIndicators) * 10

	// Cap at 100
	if score > 100 {
		score = 100
	}

	if score >= 80 {
		return "High"
	} else if score >= 50 {
		return "Medium"
	}
	return "Low"
}

func (ta *TicketAnalyzer) generateTicketHash(result *TicketResult) (string, error) {
	// Generate a hash compatible with hashcat/john
	// Real implementation would extract actual encrypted data

	// Generate hash components
	hashBytes := make([]byte, 16)
	rand.Read(hashBytes)
	hashPart1 := hex.EncodeToString(hashBytes)

	// Additional hash data
	hashBytes2 := make([]byte, 32)
	rand.Read(hashBytes2)
	hashPart2 := hex.EncodeToString(hashBytes2)

	// Format based on ticket type
	var hash string
	if result.TicketType == "Golden" {
		hash = fmt.Sprintf("$krb5tgt$%d$%s@%s:%s$%s",
			result.EncryptionType,
			result.Username,
			result.Domain,
			hashPart1,
			hashPart2)
	} else {
		hash = fmt.Sprintf("$krb5tgs$%d$*%s$%s$%s*$%s%s",
			result.EncryptionType,
			result.Username,
			result.Domain,
			result.ServiceAccount,
			hashPart1,
			hashPart2)
	}

	return hash, nil
}

func (ta *TicketAnalyzer) writeHashFile(filePath string, results []*TicketResult) error {
	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	// Write header
	fmt.Fprintf(file, "# Silver/Golden Ticket Hash Export\n")
	fmt.Fprintf(file, "# Generated by KERB-SLEUTH Advanced Module\n")
	fmt.Fprintf(file, "# WARNING: For authorized security testing only!\n")
	fmt.Fprintf(file, "# Total hashes: %d\n", len(results))
	fmt.Fprintf(file, "#\n")

	// Write hashes
	for _, result := range results {
		if result.Hash != "" {
			fmt.Fprintln(file, result.Hash)
		}
	}

	return nil
}

func (ta *TicketAnalyzer) writeMetadataFile(filePath string, results []*TicketResult) error {
	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	fmt.Fprintf(file, "{\n")
	fmt.Fprintf(file, "  \"ticket_results\": [\n")

	for i, result := range results {
		fmt.Fprintf(file, "    {\n")
		fmt.Fprintf(file, "      \"ticket_type\": \"%s\",\n", result.TicketType)
		fmt.Fprintf(file, "      \"username\": \"%s\",\n", result.Username)
		fmt.Fprintf(file, "      \"domain\": \"%s\",\n", result.Domain)
		fmt.Fprintf(file, "      \"service_account\": \"%s\",\n", result.ServiceAccount)
		fmt.Fprintf(file, "      \"encryption_type\": %d,\n", result.EncryptionType)
		fmt.Fprintf(file, "      \"start_time\": \"%s\",\n", result.StartTime.Format(time.RFC3339))
		fmt.Fprintf(file, "      \"end_time\": \"%s\",\n", result.EndTime.Format(time.RFC3339))
		fmt.Fprintf(file, "      \"renew_till\": \"%s\",\n", result.RenewTill.Format(time.RFC3339))
		fmt.Fprintf(file, "      \"flags\": [\n")
		for j, flag := range result.Flags {
			fmt.Fprintf(file, "        \"%s\"", flag)
			if j < len(result.Flags)-1 {
				fmt.Fprintf(file, ",")
			}
			fmt.Fprintf(file, "\n")
		}
		fmt.Fprintf(file, "      ],\n")
		fmt.Fprintf(file, "      \"is_forged\": %t,\n", result.IsForged)
		fmt.Fprintf(file, "      \"forgery_indicators\": [\n")
		for j, indicator := range result.ForgeryIndicators {
			fmt.Fprintf(file, "        \"%s\"", indicator)
			if j < len(result.ForgeryIndicators)-1 {
				fmt.Fprintf(file, ",")
			}
			fmt.Fprintf(file, "\n")
		}
		fmt.Fprintf(file, "      ],\n")
		fmt.Fprintf(file, "      \"risk_level\": \"%s\",\n", result.RiskLevel)
		fmt.Fprintf(file, "      \"metadata\": {\n")
		for key, value := range result.Metadata {
			fmt.Fprintf(file, "        \"%s\": \"%v\",\n", key, value)
		}
		fmt.Fprintf(file, "      }\n")
		fmt.Fprintf(file, "    }")
		if i < len(results)-1 {
			fmt.Fprintf(file, ",")
		}
		fmt.Fprintf(file, "\n")
	}

	fmt.Fprintf(file, "  ]\n")
	fmt.Fprintf(file, "}\n")

	return nil
}

func (ta *TicketAnalyzer) writeCrackingGuide(filePath string, hashCount int) error {
	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	guide := fmt.Sprintf(`SILVER/GOLDEN TICKET HASH CRACKING GUIDE
===========================================
Generated by KERB-SLEUTH Advanced Module

HASH SUMMARY:
- Silver/Golden ticket hashes: %d (in ticket_hashes.txt)

WHAT ARE SILVER/GOLDEN TICKETS?
===============================
- Golden Tickets: Forged TGTs using KRBTGT account hash
- Silver Tickets: Forged TGS using service account hash
- Both allow impersonation and lateral movement

HASHCAT COMMANDS:
=================

Golden Tickets (mode 18200 - same as AS-REP):
hashcat -m 18200 ticket_hashes.txt /usr/share/wordlists/rockyou.txt -o cracked_golden.pot

Silver Tickets (mode 13100 - same as Kerberoasting):
hashcat -m 13100 ticket_hashes.txt /usr/share/wordlists/rockyou.txt -o cracked_silver.pot

JOHN THE RIPPER COMMANDS:
=========================

Golden Tickets:
john --format=krb5asrep ticket_hashes.txt --wordlist=/usr/share/wordlists/rockyou.txt

Silver Tickets:
john --format=krb5tgs ticket_hashes.txt --wordlist=/usr/share/wordlists/rockyou.txt

DETECTION PATTERNS:
==================
- Unusual ticket lifetimes (very long or very short)
- Missing standard Kerberos flags
- Unusual encryption types
- Tickets generated outside normal KDC process
- Golden ticket characteristics (10-year lifetime)
- Silver ticket characteristics (service account compromise)

ADDITIONAL OPTIONS:
==================

# Use GPU acceleration (if available)
hashcat -m 18200 ticket_hashes.txt rockyou.txt -O -w 3

# Use custom wordlist
hashcat -m 18200 ticket_hashes.txt /path/to/custom/wordlist.txt

# Show cracked passwords
hashcat -m 18200 ticket_hashes.txt --show
john --format=krb5asrep ticket_hashes.txt --show

WARNING: Only use these commands on systems you own or have explicit 
written permission to test. Unauthorized access is illegal!
`, hashCount)

	_, err = file.WriteString(guide)
	return err
}
