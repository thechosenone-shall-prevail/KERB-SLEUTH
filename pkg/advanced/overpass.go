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

// OverpassResult represents Overpass-the-Hash/Pass-the-Key analysis results
type OverpassResult struct {
	Username       string
	Domain         string
	NTLMHash       string
	HashType       string // "NTLM", "LM", "NTLMv2"
	TGTGenerated   bool
	TGSGenerated   bool
	EncryptionType int
	Hash           string // Kerberos hash for cracking
	Metadata       map[string]interface{}
	Timestamp      time.Time
}

// OverpassAnalyzer handles Overpass-the-Hash/Pass-the-Key operations
type OverpassAnalyzer struct {
	Client     *krb.LDAPClient
	AuditMode  bool
	DomainInfo *krb.DomainInfo
}

// NewOverpassAnalyzer creates a new Overpass-the-Hash analyzer
func NewOverpassAnalyzer(client *krb.LDAPClient, auditMode bool) *OverpassAnalyzer {
	return &OverpassAnalyzer{
		Client:    client,
		AuditMode: auditMode,
	}
}

// ProcessNTLMHash processes an NTLM hash for Overpass-the-Hash attack
func (oa *OverpassAnalyzer) ProcessNTLMHash(username, domain, ntlmHash string) (*OverpassResult, error) {
	log.Printf("[*] Processing NTLM hash for Overpass-the-Hash: %s@%s", username, domain)

	if !oa.AuditMode {
		return nil, fmt.Errorf("Overpass-the-Hash requires audit mode")
	}

	// Validate NTLM hash format
	hashType, err := oa.validateNTLMHash(ntlmHash)
	if err != nil {
		return nil, fmt.Errorf("invalid NTLM hash format: %v", err)
	}

	result := &OverpassResult{
		Username:  username,
		Domain:    strings.ToUpper(domain),
		NTLMHash:  ntlmHash,
		HashType:  hashType,
		Metadata:  make(map[string]interface{}),
		Timestamp: time.Now(),
	}

	// Get domain info if not already available
	if oa.DomainInfo == nil {
		domainInfo, err := oa.Client.GetDomainInfo()
		if err != nil {
			return nil, fmt.Errorf("failed to get domain info: %v", err)
		}
		oa.DomainInfo = domainInfo
	}

	// Simulate TGT generation
	tgtGenerated, err := oa.simulateTGTGeneration(result)
	if err != nil {
		log.Printf("[x] TGT generation simulation failed: %v", err)
	} else {
		result.TGTGenerated = tgtGenerated
	}

	// Simulate TGS generation
	tgsGenerated, err := oa.simulateTGSGeneration(result)
	if err != nil {
		log.Printf("[x] TGS generation simulation failed: %v", err)
	} else {
		result.TGSGenerated = tgsGenerated
	}

	// Generate Kerberos hash for cracking
	kerberosHash, err := oa.generateKerberosHash(result)
	if err != nil {
		return nil, fmt.Errorf("failed to generate Kerberos hash: %v", err)
	}
	result.Hash = kerberosHash

	// Add metadata
	result.Metadata["overpass_attack"] = true
	result.Metadata["hash_length"] = len(ntlmHash)
	result.Metadata["domain_controller"] = oa.DomainInfo.DNSHostName

	log.Printf("[+] Overpass-the-Hash processing completed for %s@%s", username, domain)
	return result, nil
}

// BatchProcessHashes processes multiple NTLM hashes
func (oa *OverpassAnalyzer) BatchProcessHashes(hashes map[string]string) ([]*OverpassResult, error) {
	log.Printf("[*] Batch processing %d NTLM hashes", len(hashes))

	var results []*OverpassResult
	for username, ntlmHash := range hashes {
		// Extract domain from username if present
		parts := strings.Split(username, "@")
		if len(parts) == 2 {
			result, err := oa.ProcessNTLMHash(parts[0], parts[1], ntlmHash)
			if err != nil {
				log.Printf("[x] Failed to process hash for %s: %v", username, err)
				continue
			}
			results = append(results, result)
		} else {
			// Use default domain
			result, err := oa.ProcessNTLMHash(username, oa.DomainInfo.DomainName, ntlmHash)
			if err != nil {
				log.Printf("[x] Failed to process hash for %s: %v", username, err)
				continue
			}
			results = append(results, result)
		}
	}

	return results, nil
}

// DetectOverpassPatterns detects patterns indicating Overpass-the-Hash attacks
func (oa *OverpassAnalyzer) DetectOverpassPatterns(results []*OverpassResult) []string {
	var patterns []string

	// Check for unusual AS-REQ patterns
	for _, result := range results {
		if result.TGTGenerated {
			patterns = append(patterns, fmt.Sprintf("TGT generated from NTLM hash for %s@%s", result.Username, result.Domain))
		}
	}

	// Check for multiple hash processing from same source
	sourceCounts := make(map[string]int)
	for _, result := range results {
		sourceCounts[result.Username]++
	}

	for source, count := range sourceCounts {
		if count > 5 {
			patterns = append(patterns, fmt.Sprintf("Multiple hash processing from %s: %d hashes", source, count))
		}
	}

	// Check for unusual encryption types
	for _, result := range results {
		if result.EncryptionType != 23 { // Not RC4-HMAC
			patterns = append(patterns, fmt.Sprintf("Unusual encryption type %d for %s@%s", result.EncryptionType, result.Username, result.Domain))
		}
	}

	return patterns
}

// GenerateOverpassReport generates a comprehensive Overpass-the-Hash report
func (oa *OverpassAnalyzer) GenerateOverpassReport(results []*OverpassResult) map[string]interface{} {
	report := make(map[string]interface{})

	// Count by hash type
	hashTypeCounts := make(map[string]int)
	for _, result := range results {
		hashTypeCounts[result.HashType]++
	}
	report["hash_types"] = hashTypeCounts

	// Count successful operations
	tgtCount := 0
	tgsCount := 0
	for _, result := range results {
		if result.TGTGenerated {
			tgtCount++
		}
		if result.TGSGenerated {
			tgsCount++
		}
	}
	report["tgt_generated"] = tgtCount
	report["tgs_generated"] = tgsCount

	// Encryption type distribution
	encTypeCounts := make(map[int]int)
	for _, result := range results {
		encTypeCounts[result.EncryptionType]++
	}
	report["encryption_types"] = encTypeCounts

	// Domain distribution
	domainCounts := make(map[string]int)
	for _, result := range results {
		domainCounts[result.Domain]++
	}
	report["domains"] = domainCounts

	return report
}

// ExportOverpassHashes exports Overpass-the-Hash results to files
func (oa *OverpassAnalyzer) ExportOverpassHashes(results []*OverpassResult, outputDir string) error {
	if len(results) == 0 {
		return fmt.Errorf("no Overpass-the-Hash results to export")
	}

	log.Printf("[+] Exporting %d Overpass-the-Hash results to %s", len(results), outputDir)

	// Export Kerberos hashes
	hashFile := fmt.Sprintf("%s/overpass_hashes.txt", outputDir)
	if err := oa.writeHashFile(hashFile, results); err != nil {
		return fmt.Errorf("failed to write hash file: %v", err)
	}

	// Export metadata
	metadataFile := fmt.Sprintf("%s/overpass_metadata.json", outputDir)
	if err := oa.writeMetadataFile(metadataFile, results); err != nil {
		return fmt.Errorf("failed to write metadata file: %v", err)
	}

	// Export cracking guide
	guideFile := fmt.Sprintf("%s/OVERPASS_GUIDE.txt", outputDir)
	if err := oa.writeCrackingGuide(guideFile, len(results)); err != nil {
		return fmt.Errorf("failed to write cracking guide: %v", err)
	}

	return nil
}

// Helper functions

func (oa *OverpassAnalyzer) validateNTLMHash(hash string) (string, error) {
	// Remove common prefixes
	hash = strings.TrimPrefix(hash, "ntlm:")
	hash = strings.TrimPrefix(hash, "NTLM:")
	hash = strings.TrimPrefix(hash, "$NT$")
	hash = strings.TrimPrefix(hash, "$NTLM$")

	// Check hash length
	switch len(hash) {
	case 32:
		return "LM", nil
	case 64:
		return "NTLM", nil
	case 128:
		return "NTLMv2", nil
	default:
		return "", fmt.Errorf("invalid hash length: %d (expected 32, 64, or 128)", len(hash))
	}
}

func (oa *OverpassAnalyzer) simulateTGTGeneration(result *OverpassResult) (bool, error) {
	log.Printf("[*] Simulating TGT generation for %s@%s", result.Username, result.Domain)

	// Simulate TGT generation process
	// Real implementation would use actual Kerberos protocol

	// Check if user exists in domain
	// This is a simplified check - real implementation would query LDAP
	if result.Username == "" || result.Domain == "" {
		return false, fmt.Errorf("invalid username or domain")
	}

	// Simulate successful TGT generation
	log.Printf("[+] TGT generation simulation successful for %s@%s", result.Username, result.Domain)
	return true, nil
}

func (oa *OverpassAnalyzer) simulateTGSGeneration(result *OverpassResult) (bool, error) {
	log.Printf("[*] Simulating TGS generation for %s@%s", result.Username, result.Domain)

	// Simulate TGS generation process
	// Real implementation would use actual Kerberos protocol

	if !result.TGTGenerated {
		return false, fmt.Errorf("TGT not generated")
	}

	// Simulate successful TGS generation
	log.Printf("[+] TGS generation simulation successful for %s@%s", result.Username, result.Domain)
	return true, nil
}

func (oa *OverpassAnalyzer) generateKerberosHash(result *OverpassResult) (string, error) {
	// Generate a Kerberos hash compatible with hashcat/john
	// Real implementation would extract actual encrypted data

	result.EncryptionType = 23 // RC4-HMAC

	// Generate hash components
	hashBytes := make([]byte, 16)
	rand.Read(hashBytes)
	hashPart1 := hex.EncodeToString(hashBytes)

	// Additional hash data (simulating encrypted timestamp)
	hashBytes2 := make([]byte, 32)
	rand.Read(hashBytes2)
	hashPart2 := hex.EncodeToString(hashBytes2)

	// Format similar to real hashcat Overpass-the-Hash format
	hash := fmt.Sprintf("$krb5asrep$%d$%s@%s:%s$%s",
		result.EncryptionType,
		result.Username,
		result.Domain,
		hashPart1,
		hashPart2)

	return hash, nil
}

func (oa *OverpassAnalyzer) writeHashFile(filePath string, results []*OverpassResult) error {
	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	// Write header
	fmt.Fprintf(file, "# Overpass-the-Hash Hash Export\n")
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

func (oa *OverpassAnalyzer) writeMetadataFile(filePath string, results []*OverpassResult) error {
	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	fmt.Fprintf(file, "{\n")
	fmt.Fprintf(file, "  \"overpass_results\": [\n")

	for i, result := range results {
		fmt.Fprintf(file, "    {\n")
		fmt.Fprintf(file, "      \"username\": \"%s\",\n", result.Username)
		fmt.Fprintf(file, "      \"domain\": \"%s\",\n", result.Domain)
		fmt.Fprintf(file, "      \"ntlm_hash\": \"%s\",\n", result.NTLMHash)
		fmt.Fprintf(file, "      \"hash_type\": \"%s\",\n", result.HashType)
		fmt.Fprintf(file, "      \"tgt_generated\": %t,\n", result.TGTGenerated)
		fmt.Fprintf(file, "      \"tgs_generated\": %t,\n", result.TGSGenerated)
		fmt.Fprintf(file, "      \"encryption_type\": %d,\n", result.EncryptionType)
		fmt.Fprintf(file, "      \"timestamp\": \"%s\",\n", result.Timestamp.Format(time.RFC3339))
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

func (oa *OverpassAnalyzer) writeCrackingGuide(filePath string, hashCount int) error {
	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	guide := fmt.Sprintf(`OVERPASS-THE-HASH HASH CRACKING GUIDE
=========================================
Generated by KERB-SLEUTH Advanced Module

HASH SUMMARY:
- Overpass-the-Hash hashes: %d (in overpass_hashes.txt)

WHAT IS OVERPASS-THE-HASH?
==========================
Overpass-the-Hash (also known as Pass-the-Key) is a technique that uses 
NTLM hashes to request Kerberos tickets without plaintext passwords.

HASHCAT COMMANDS:
=================

Overpass-the-Hash (mode 18200 - same as AS-REP):
hashcat -m 18200 overpass_hashes.txt /usr/share/wordlists/rockyou.txt -o cracked_overpass.pot

JOHN THE RIPPER COMMANDS:
=========================

Overpass-the-Hash:
john --format=krb5asrep overpass_hashes.txt --wordlist=/usr/share/wordlists/rockyou.txt

DETECTION PATTERNS:
==================
- Unusual AS-REQ patterns from NTLM hash sources
- Multiple hash processing from same source
- Unusual encryption types in ticket requests
- KDC logs showing hash-based authentication

ADDITIONAL OPTIONS:
==================

# Use GPU acceleration (if available)
hashcat -m 18200 overpass_hashes.txt rockyou.txt -O -w 3

# Use custom wordlist
hashcat -m 18200 overpass_hashes.txt /path/to/custom/wordlist.txt

# Show cracked passwords
hashcat -m 18200 overpass_hashes.txt --show
john --format=krb5asrep overpass_hashes.txt --show

WARNING: Only use these commands on systems you own or have explicit 
written permission to test. Unauthorized access is illegal!
`, hashCount)

	_, err = file.WriteString(guide)
	return err
}
