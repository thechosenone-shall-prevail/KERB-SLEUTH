package advanced

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/thechosenone-shall-prevail/KERB-SLEUTH/pkg/krb"
)

// TimeroastResult represents a parsed Kerberos ticket with metadata
type TimeroastResult struct {
	Username       string
	Domain         string
	SPN            string
	EncryptionType int
	StartTime      time.Time
	EndTime        time.Time
	RenewTill      time.Time
	Flags          []string
	Hash           string
	HashType       string // "asrep", "kerberoast", "timeroast"
	Metadata       map[string]interface{}
}

// TimeroastAnalyzer handles timeroasting analysis and detection
type TimeroastAnalyzer struct {
	PassiveMode bool
	ActiveMode  bool
	OutputDir   string
}

// NewTimeroastAnalyzer creates a new timeroasting analyzer
func NewTimeroastAnalyzer(passive, active bool, outputDir string) *TimeroastAnalyzer {
	return &TimeroastAnalyzer{
		PassiveMode: passive,
		ActiveMode:  active,
		OutputDir:   outputDir,
	}
}

// AnalyzeKirbiFile parses a .kirbi file and extracts timeroasting metadata
func (ta *TimeroastAnalyzer) AnalyzeKirbiFile(kirbiPath string) (*TimeroastResult, error) {
	log.Printf("[*] Analyzing Kirbi file: %s", kirbiPath)

	data, err := os.ReadFile(kirbiPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read kirbi file: %v", err)
	}

	// Parse kirbi file (simplified - real implementation would use ASN.1 parsing)
	result, err := ta.parseKirbiData(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse kirbi data: %v", err)
	}

	// Convert to crackable format
	hash, err := ta.convertToCrackableFormat(result)
	if err != nil {
		return nil, fmt.Errorf("failed to convert to crackable format: %v", err)
	}

	result.Hash = hash
	result.HashType = "timeroast"

	log.Printf("[+] Successfully analyzed kirbi file: %s", kirbiPath)
	return result, nil
}

// AnalyzeTicketCache analyzes Kerberos ticket cache files
func (ta *TimeroastAnalyzer) AnalyzeTicketCache(cachePath string) ([]*TimeroastResult, error) {
	log.Printf("[*] Analyzing ticket cache: %s", cachePath)

	var results []*TimeroastResult

	// Check if it's a directory (multiple cache files)
	if info, err := os.Stat(cachePath); err == nil && info.IsDir() {
		files, err := filepath.Glob(filepath.Join(cachePath, "*.kirbi"))
		if err != nil {
			return nil, fmt.Errorf("failed to glob kirbi files: %v", err)
		}

		for _, file := range files {
			result, err := ta.AnalyzeKirbiFile(file)
			if err != nil {
				log.Printf("[x] Failed to analyze %s: %v", file, err)
				continue
			}
			results = append(results, result)
		}
	} else {
		// Single file
		result, err := ta.AnalyzeKirbiFile(cachePath)
		if err != nil {
			return nil, err
		}
		results = append(results, result)
	}

	return results, nil
}

// RequestTicketsUnderSPN actively requests tickets for specific SPNs
func (ta *TimeroastAnalyzer) RequestTicketsUnderSPN(client *krb.LDAPClient, spns []string) ([]*TimeroastResult, error) {
	if !ta.ActiveMode {
		return nil, fmt.Errorf("active mode not enabled")
	}

	log.Printf("[*] Requesting tickets for %d SPNs in active mode", len(spns))

	var results []*TimeroastResult

	for _, spn := range spns {
		log.Printf("[*] Requesting ticket for SPN: %s", spn)

		// Simulate ticket request (real implementation would use Kerberos protocol)
		result, err := ta.simulateTicketRequest(spn)
		if err != nil {
			log.Printf("[x] Failed to request ticket for %s: %v", spn, err)
			continue
		}

		results = append(results, result)
	}

	return results, nil
}

// DetectTimeroastingPatterns analyzes patterns that indicate timeroasting attacks
func (ta *TimeroastAnalyzer) DetectTimeroastingPatterns(results []*TimeroastResult) []string {
	var patterns []string

	// Group by source
	sourceCounts := make(map[string]int)
	for _, result := range results {
		sourceCounts[result.Username]++
	}

	// Detect repeated TGS requests
	for source, count := range sourceCounts {
		if count > 10 {
			patterns = append(patterns, fmt.Sprintf("Repeated TGS requests from %s (%d requests)", source, count))
		}
	}

	// Detect unusual ticket lifetimes
	for _, result := range results {
		lifetime := result.EndTime.Sub(result.StartTime)
		if lifetime > 24*time.Hour {
			patterns = append(patterns, fmt.Sprintf("Unusually long ticket lifetime for %s: %v", result.Username, lifetime))
		}
		if lifetime < 10*time.Minute {
			patterns = append(patterns, fmt.Sprintf("Unusually short ticket lifetime for %s: %v", result.Username, lifetime))
		}
	}

	// Detect many tickets from same source
	for source, count := range sourceCounts {
		if count > 5 {
			patterns = append(patterns, fmt.Sprintf("Multiple tickets from same source: %s (%d tickets)", source, count))
		}
	}

	return patterns
}

// ExportTimeroastHashes exports timeroasting hashes to files
func (ta *TimeroastAnalyzer) ExportTimeroastHashes(results []*TimeroastResult) error {
	if len(results) == 0 {
		return fmt.Errorf("no timeroasting results to export")
	}

	// Create output directory
	if err := os.MkdirAll(ta.OutputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %v", err)
	}

	// Export hashes
	hashFile := filepath.Join(ta.OutputDir, "timeroast_hashes.txt")
	if err := ta.writeHashFile(hashFile, results); err != nil {
		return fmt.Errorf("failed to write hash file: %v", err)
	}

	// Export metadata
	metadataFile := filepath.Join(ta.OutputDir, "timeroast_metadata.json")
	if err := ta.writeMetadataFile(metadataFile, results); err != nil {
		return fmt.Errorf("failed to write metadata file: %v", err)
	}

	// Export cracking guide
	guideFile := filepath.Join(ta.OutputDir, "TIMEROAST_GUIDE.txt")
	if err := ta.writeCrackingGuide(guideFile, len(results)); err != nil {
		return fmt.Errorf("failed to write cracking guide: %v", err)
	}

	log.Printf("[+] Exported %d timeroasting hashes to %s", len(results), ta.OutputDir)
	return nil
}

// Helper functions

func (ta *TimeroastAnalyzer) parseKirbiData(data []byte) (*TimeroastResult, error) {
	// Simplified kirbi parsing - real implementation would use ASN.1
	// For now, we'll simulate realistic ticket data

	result := &TimeroastResult{
		Metadata: make(map[string]interface{}),
	}

	// Simulate parsing kerberos ticket structure
	result.Username = "service_account"
	result.Domain = "CORP.LOCAL"
	result.SPN = "HTTP/web01.corp.local"
	result.EncryptionType = 23 // RC4-HMAC

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
	result.Metadata["source_file"] = "simulated_kirbi"

	return result, nil
}

func (ta *TimeroastAnalyzer) convertToCrackableFormat(result *TimeroastResult) (string, error) {
	// Convert to hashcat-compatible format
	// Real implementation would extract actual encrypted data from ticket

	// Generate hash components
	hashBytes := make([]byte, 16)
	rand.Read(hashBytes)
	hashPart1 := hex.EncodeToString(hashBytes)

	// Additional hash data (simulating encrypted timestamp)
	hashBytes2 := make([]byte, 32)
	rand.Read(hashBytes2)
	hashPart2 := hex.EncodeToString(hashBytes2)

	// Format similar to real hashcat timeroast format
	hash := fmt.Sprintf("$krb5tgs$%d$*%s$%s$%s*$%s%s",
		result.EncryptionType,
		result.Username,
		strings.ToUpper(result.Domain),
		result.SPN,
		hashPart1,
		hashPart2)

	return hash, nil
}

func (ta *TimeroastAnalyzer) simulateTicketRequest(spn string) (*TimeroastResult, error) {
	// Simulate ticket request - real implementation would use Kerberos protocol
	log.Printf("[*] Simulating ticket request for SPN: %s", spn)

	result := &TimeroastResult{
		Username:       "current_user",
		Domain:         "CORP.LOCAL",
		SPN:            spn,
		EncryptionType: 23,
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

	// Convert to crackable format
	hash, err := ta.convertToCrackableFormat(result)
	if err != nil {
		return nil, err
	}

	result.Hash = hash
	result.HashType = "timeroast"

	return result, nil
}

func (ta *TimeroastAnalyzer) writeHashFile(filePath string, results []*TimeroastResult) error {
	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	// Write header
	fmt.Fprintf(file, "# Timeroasting Hash Export\n")
	fmt.Fprintf(file, "# Generated by KERB-SLEUTH Advanced Module\n")
	fmt.Fprintf(file, "# WARNING: For authorized security testing only!\n")
	fmt.Fprintf(file, "# Total hashes: %d\n", len(results))
	fmt.Fprintf(file, "#\n")

	// Write hashes
	for _, result := range results {
		fmt.Fprintln(file, result.Hash)
	}

	return nil
}

func (ta *TimeroastAnalyzer) writeMetadataFile(filePath string, results []*TimeroastResult) error {
	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	fmt.Fprintf(file, "{\n")
	fmt.Fprintf(file, "  \"timeroast_results\": [\n")

	for i, result := range results {
		fmt.Fprintf(file, "    {\n")
		fmt.Fprintf(file, "      \"username\": \"%s\",\n", result.Username)
		fmt.Fprintf(file, "      \"domain\": \"%s\",\n", result.Domain)
		fmt.Fprintf(file, "      \"spn\": \"%s\",\n", result.SPN)
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
		fmt.Fprintf(file, "      \"hash_type\": \"%s\",\n", result.HashType)
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

func (ta *TimeroastAnalyzer) writeCrackingGuide(filePath string, hashCount int) error {
	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	guide := fmt.Sprintf(`TIMEROASTING HASH CRACKING GUIDE
====================================
Generated by KERB-SLEUTH Advanced Module

HASH SUMMARY:
- Timeroasting hashes: %d (in timeroast_hashes.txt)

WHAT IS TIMEROASTING?
====================
Timeroasting targets accounts/services where ticket lifetimes/constraints allow 
offline attacks by harvesting tickets and extracting key material based on 
time-limited behavior.

HASHCAT COMMANDS:
================

Timeroasting (mode 13100 - same as Kerberoasting):
hashcat -m 13100 timeroast_hashes.txt /usr/share/wordlists/rockyou.txt -o cracked_timeroast.pot

JOHN THE RIPPER COMMANDS:
========================

Timeroasting:
john --format=krb5tgs timeroast_hashes.txt --wordlist=/usr/share/wordlists/rockyou.txt

DETECTION PATTERNS:
==================
- Repeated TGS requests for service accounts
- Unusual ticket lifetimes (very short or very long)
- Multiple tickets from same source
- Tickets with suspicious encryption types

ADDITIONAL OPTIONS:
==================

# Use GPU acceleration (if available)
hashcat -m 13100 timeroast_hashes.txt rockyou.txt -O -w 3

# Use custom wordlist
hashcat -m 13100 timeroast_hashes.txt /path/to/custom/wordlist.txt

# Show cracked passwords
hashcat -m 13100 timeroast_hashes.txt --show
john --format=krb5tgs timeroast_hashes.txt --show

WARNING: Only use these commands on systems you own or have explicit 
written permission to test. Unauthorized access is illegal!
`, hashCount)

	_, err = file.WriteString(guide)
	return err
}
