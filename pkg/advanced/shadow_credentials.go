package advanced

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"

	"github.com/go-ldap/ldap/v3"
	"github.com/thechosenone-shall-prevail/cold-relay/pkg/krb"
)

// ShadowCredentialsResult represents shadow credentials analysis results
type ShadowCredentialsResult struct {
	TargetDN         string   `json:"target_dn"`
	TargetSAM        string   `json:"target_sam"`
	DeviceID         string   `json:"device_id,omitempty"`
	KeyCredential    string   `json:"key_credential,omitempty"`
	KeyID            string   `json:"key_id,omitempty"`
	CreationTime     string   `json:"creation_time,omitempty"`
	RiskScore        int      `json:"risk_score"`
	RiskLevel        string   `json:"risk_level"`
	Exploitability   []string `json:"exploitability"`
	Recommendations  []string `json:"recommendations"`
}

// ShadowCredentialsAnalyzer handles shadow credentials (Key Trust AD mapping) analysis
type ShadowCredentialsAnalyzer struct {
	Client    *krb.LDAPClient
	AuditMode bool
}

// NewShadowCredentialsAnalyzer creates a new shadow credentials analyzer
func NewShadowCredentialsAnalyzer(client *krb.LDAPClient, auditMode bool) *ShadowCredentialsAnalyzer {
	return &ShadowCredentialsAnalyzer{
		Client:    client,
		AuditMode: auditMode,
	}
}

// EnumerateShadowCredentials enumerates objects with msDS-KeyCredentialLink attribute
func (sca *ShadowCredentialsAnalyzer) EnumerateShadowCredentials() ([]*ShadowCredentialsResult, error) {
	log.Printf("[*] Enumerating shadow credentials (msDS-KeyCredentialLink)...")

	// Check if client is available
	if sca.Client == nil || sca.Client.GetConnection() == nil {
		log.Printf("[!] LDAP client not available, returning empty results")
		return []*ShadowCredentialsResult{}, nil
	}

	// Search for objects with msDS-KeyCredentialLink
	searchFilter := "(msDS-KeyCredentialLink=*)"
	attributes := []string{
		"distinguishedName",
		"sAMAccountName",
		"objectClass",
		"msDS-KeyCredentialLink",
	}

	entries, err := sca.Client.SearchSubtreePaged(searchFilter, attributes, 500)
	if err != nil {
		return nil, fmt.Errorf("LDAP search failed: %v", err)
	}

	log.Printf("[+] Found %d objects with shadow credentials", len(entries))

	var results []*ShadowCredentialsResult
	for _, entry := range entries {
		result, err := sca.analyzeShadowCredential(entry)
		if err != nil {
			log.Printf("[x] Failed to analyze shadow credential for %s: %v", entry.DN, err)
			continue
		}
		results = append(results, result)
	}

	return results, nil
}

// AnalyzeShadowCredentialRisk analyzes risk for a specific object's shadow credentials
func (sca *ShadowCredentialsAnalyzer) AnalyzeShadowCredentialRisk(targetDN string) (*ShadowCredentialsResult, error) {
	log.Printf("[*] Analyzing shadow credential risk for: %s", targetDN)

	searchFilter := fmt.Sprintf("(distinguishedName=%s)", ldap.EscapeFilter(targetDN))
	searchRequest := ldap.NewSearchRequest(
		sca.Client.GetBaseDN(),
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, 0, false,
		searchFilter,
		[]string{"distinguishedName", "sAMAccountName", "objectClass", "msDS-KeyCredentialLink"},
		nil,
	)

	sr, err := sca.Client.GetConnection().Search(searchRequest)
	if err != nil {
		return nil, fmt.Errorf("LDAP search failed: %v", err)
	}

	if len(sr.Entries) == 0 {
		return nil, fmt.Errorf("object not found: %s", targetDN)
	}

	return sca.analyzeShadowCredential(sr.Entries[0])
}

// DetectShadowCredentialAbuse detects potential shadow credential abuse patterns
func (sca *ShadowCredentialsAnalyzer) DetectShadowCredentialAbuse(results []*ShadowCredentialsResult) []string {
	var patterns []string

	for _, result := range results {
		if result.RiskScore > 80 {
			patterns = append(patterns, fmt.Sprintf("High-risk shadow credential on: %s (score: %d)", result.TargetSAM, result.RiskScore))
		}

		if len(result.Exploitability) > 0 {
			for _, exp := range result.Exploitability {
				patterns = append(patterns, fmt.Sprintf("Exploitable shadow credential: %s - %s", result.TargetSAM, exp))
			}
		}
	}

	return patterns
}

// Helper functions

func (sca *ShadowCredentialsAnalyzer) analyzeShadowCredential(entry *ldap.Entry) (*ShadowCredentialsResult, error) {
	result := &ShadowCredentialsResult{
		TargetDN:        entry.DN,
		TargetSAM:       entry.GetAttributeValue("sAMAccountName"),
		Exploitability:  []string{},
		Recommendations: []string{},
	}

	// Parse msDS-KeyCredentialLink
	keyCredentialLinks := entry.GetAttributeValues("msDS-KeyCredentialLink")
	if len(keyCredentialLinks) > 0 {
		for _, link := range keyCredentialLinks {
			parsed, err := sca.parseKeyCredentialLink(link)
			if err != nil {
				log.Printf("[!] Failed to parse key credential link: %v", err)
				continue
			}

			if result.DeviceID == "" {
				result.DeviceID = parsed.DeviceID
			}
			if result.KeyID == "" {
				result.KeyID = parsed.KeyID
			}
			if result.CreationTime == "" {
				result.CreationTime = parsed.CreationTime
			}
			result.KeyCredential = link
		}
	}

	// Determine object type for risk assessment
	objectClasses := entry.GetAttributeValues("objectClass")
	isUser := false
	isComputer := false
	for _, oc := range objectClasses {
		if oc == "user" {
			isUser = true
		}
		if oc == "computer" {
			isComputer = true
		}
	}

	// Calculate risk score
	result.RiskScore = sca.calculateRiskScore(result, isUser, isComputer)

	// Determine risk level
	result.RiskLevel = sca.determineRiskLevel(result.RiskScore)

	// Generate exploitability paths
	result.Exploitability = sca.generateExploitabilityPaths(result, isUser, isComputer)

	// Generate recommendations
	result.Recommendations = sca.generateRecommendations(result, isUser, isComputer)

	return result, nil
}

type KeyCredentialLink struct {
	DeviceID     string
	KeyID        string
	CreationTime string
}

func (sca *ShadowCredentialsAnalyzer) parseKeyCredentialLink(link string) (*KeyCredentialLink, error) {
	// msDS-KeyCredentialLink is a DN that references the key credential object
	// Format: CN=<DeviceID>,CN=Key Credentials,CN=<TargetDN>
	// We need to extract the device ID and potentially query the key credential object

	// For now, extract the CN (DeviceID) from the DN
	parsed := &KeyCredentialLink{
		DeviceID:     "",
		KeyID:        "",
		CreationTime: "",
	}

	// Simple DN parsing to extract CN
	parts := splitDN(link)
	for i, part := range parts {
		if len(part) > 3 && part[:3] == "CN=" {
			if i == 0 {
				parsed.DeviceID = part[3:]
			}
		}
	}

	return parsed, nil
}

func splitDN(dn string) []string {
	var parts []string
	current := ""
	for _, c := range dn {
		if c == ',' {
			parts = append(parts, current)
			current = ""
		} else {
			current += string(c)
		}
	}
	if current != "" {
		parts = append(parts, current)
	}
	return parts
}

func (sca *ShadowCredentialsAnalyzer) calculateRiskScore(result *ShadowCredentialsResult, isUser, isComputer bool) int {
	score := 0

	// Base score for having shadow credentials
	score += 40

	// Higher risk for privileged accounts
	if isUser {
		score += 20
	}
	if isComputer {
		score += 15
	}

	// Check if target is likely privileged (based on SAM name)
	sam := result.TargetSAM
	lowerSAM := lower(sam)
	if contains(lowerSAM, "admin") || contains(lowerSAM, "administrator") || contains(lowerSAM, "svc") || contains(lowerSAM, "service") {
		score += 25
	}

	// Cap at 100
	if score > 100 {
		score = 100
	}

	return score
}

func (sca *ShadowCredentialsAnalyzer) determineRiskLevel(score int) string {
	if score >= 80 {
		return "Critical"
	} else if score >= 60 {
		return "High"
	} else if score >= 40 {
		return "Medium"
	}
	return "Low"
}

func (sca *ShadowCredentialsAnalyzer) generateExploitabilityPaths(result *ShadowCredentialsResult, isUser, isComputer bool) []string {
	var paths []string

	if result.DeviceID != "" {
		paths = append(paths, fmt.Sprintf("Shadow credential allows passwordless authentication via device: %s", result.DeviceID))
	}

	if isUser {
		paths = append(paths, "Key Trust AD mapping allows authentication without password knowledge")
	}

	if isComputer {
		paths = append(paths, "Computer account shadow credential may allow lateral movement")
	}

	return paths
}

func (sca *ShadowCredentialsAnalyzer) generateRecommendations(result *ShadowCredentialsResult, isUser, isComputer bool) []string {
	var recs []string

	recs = append(recs, "Audit all devices registered via shadow credentials")
	recs = append(recs, "Review msDS-KeyCredentialLink attribute for unauthorized entries")
	recs = append(recs, "Implement MFA to reduce shadow credential abuse risk")

	if isUser {
		recs = append(recs, "Review user account for suspicious device registrations")
	}

	if isComputer {
		recs = append(recs, "Verify computer account's shadow credential is legitimate")
	}

	return recs
}

func lower(s string) string {
	result := ""
	for _, c := range s {
		if c >= 'A' && c <= 'Z' {
			result += string(c + 32)
		} else {
			result += string(c)
		}
	}
	return result
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && findSubstring(s, substr)
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		match := true
		for j := 0; j < len(substr); j++ {
			if s[i+j] != substr[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// GenerateShadowCredentialsReport generates a comprehensive shadow credentials report
func (sca *ShadowCredentialsAnalyzer) GenerateShadowCredentialsReport(results []*ShadowCredentialsResult) map[string]interface{} {
	report := make(map[string]interface{})

	report["total_shadow_credentials"] = len(results)

	highRisk := []*ShadowCredentialsResult{}
	criticalRisk := []*ShadowCredentialsResult{}

	for _, result := range results {
		if result.RiskLevel == "Critical" {
			criticalRisk = append(criticalRisk, result)
		} else if result.RiskLevel == "High" {
			highRisk = append(highRisk, result)
		}
	}

	report["critical_risk_count"] = len(criticalRisk)
	report["high_risk_count"] = len(highRisk)
	report["critical_risk_targets"] = criticalRisk
	report["high_risk_targets"] = highRisk

	// Abuse patterns
	patterns := sca.DetectShadowCredentialAbuse(results)
	report["abuse_patterns"] = patterns

	return report
}

// ExportShadowCredentialsToJSON exports shadow credentials results to JSON
func (sca *ShadowCredentialsAnalyzer) ExportShadowCredentialsToJSON(results []*ShadowCredentialsResult, outputPath string) error {
	data, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %v", err)
	}

	// In a real implementation, write to file
	log.Printf("[+] Shadow credentials JSON export ready (%d bytes)", len(data))

	return nil
}

// ParseKeyCredentialObject parses a key credential object from LDAP
func (sca *ShadowCredentialsAnalyzer) ParseKeyCredentialObject(dn string) (map[string]interface{}, error) {
	searchRequest := ldap.NewSearchRequest(
		sca.Client.GetBaseDN(),
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, 0, false,
		fmt.Sprintf("(distinguishedName=%s)", ldap.EscapeFilter(dn)),
		[]string{"objectGUID", "msDS-KeyCredentialLink", "msDS-DeviceId"},
		nil,
	)

	sr, err := sca.Client.GetConnection().Search(searchRequest)
	if err != nil {
		return nil, fmt.Errorf("LDAP search failed: %v", err)
	}

	if len(sr.Entries) == 0 {
		return nil, fmt.Errorf("key credential object not found: %s", dn)
	}

	entry := sr.Entries[0]
	result := make(map[string]interface{})
	result["dn"] = entry.DN
	result["objectGUID"] = entry.GetAttributeValue("objectGUID")
	result["deviceId"] = entry.GetAttributeValue("msDS-DeviceId")

	// Decode msDS-KeyCredentialLink if present
	keyLinks := entry.GetAttributeValues("msDS-KeyCredentialLink")
	if len(keyLinks) > 0 {
		var decoded []map[string]interface{}
		for _, link := range keyLinks {
			// Attempt to decode if it's base64 encoded
			if decodedBytes, err := base64.StdEncoding.DecodeString(link); err == nil {
				var decodedData map[string]interface{}
				if err := json.Unmarshal(decodedBytes, &decodedData); err == nil {
					decoded = append(decoded, decodedData)
				}
			}
		}
		if len(decoded) > 0 {
			result["decodedCredentials"] = decoded
		}
	}

	return result, nil
}
