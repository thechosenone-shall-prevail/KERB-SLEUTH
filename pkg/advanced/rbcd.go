package advanced

import (
	"fmt"
	"log"
	"strings"

	"github.com/go-ldap/ldap/v3"
	"github.com/thechosenone-shall-prevail/KERB-SLEUTH/pkg/krb"
)

// RBCDResult represents Resource-Based Constrained Delegation analysis results
type RBCDResult struct {
	TargetDN              string
	TargetName            string
	AllowedToActOn        []string
	ServicePrincipalNames []string
	ExploitabilityScore   int
	RiskLevel             string
	ExploitationPath      []string
	Recommendations       []string
}

// RBCDAnalyzer handles RBCD enumeration and analysis
type RBCDAnalyzer struct {
	Client    *krb.LDAPClient
	AuditMode bool
}

// NewRBCDAnalyzer creates a new RBCD analyzer
func NewRBCDAnalyzer(client *krb.LDAPClient, auditMode bool) *RBCDAnalyzer {
	return &RBCDAnalyzer{
		Client:    client,
		AuditMode: auditMode,
	}
}

// EnumerateRBCDTargets enumerates all objects with RBCD configurations
func (ra *RBCDAnalyzer) EnumerateRBCDTargets() ([]*RBCDResult, error) {
	log.Printf("🔍 Enumerating RBCD targets...")

	// Check if client is available
	if ra.Client == nil || ra.Client.GetConnection() == nil {
		log.Printf("⚠️  LDAP client not available, returning empty results")
		return []*RBCDResult{}, nil
	}

	// Search for objects with msDS-AllowedToActOnBehalfOfOtherIdentity
	searchFilter := "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)"
	attributes := []string{
		"distinguishedName",
		"sAMAccountName",
		"msDS-AllowedToActOnBehalfOfOtherIdentity",
		"servicePrincipalName",
		"objectClass",
		"userAccountControl",
	}

	searchRequest := ldap.NewSearchRequest(
		ra.Client.GetBaseDN(),
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, 0, false,
		searchFilter,
		attributes,
		nil,
	)

	sr, err := ra.Client.GetConnection().Search(searchRequest)
	if err != nil {
		return nil, fmt.Errorf("LDAP search failed: %v", err)
	}

	log.Printf("Found %d objects with RBCD configurations", len(sr.Entries))

	var results []*RBCDResult
	for _, entry := range sr.Entries {
		result, err := ra.analyzeRBCDTarget(entry)
		if err != nil {
			log.Printf("⚠️  Failed to analyze RBCD target %s: %v", entry.DN, err)
			continue
		}
		results = append(results, result)
	}

	return results, nil
}

// AnalyzeSpecificTarget analyzes RBCD configuration for a specific target
func (ra *RBCDAnalyzer) AnalyzeSpecificTarget(targetDN string) (*RBCDResult, error) {
	log.Printf("🎯 Analyzing specific RBCD target: %s", targetDN)

	searchRequest := ldap.NewSearchRequest(
		targetDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0, 0, false,
		"(objectClass=*)",
		[]string{
			"distinguishedName",
			"sAMAccountName",
			"msDS-AllowedToActOnBehalfOfOtherIdentity",
			"servicePrincipalName",
			"objectClass",
			"userAccountControl",
		},
		nil,
	)

	sr, err := ra.Client.GetConnection().Search(searchRequest)
	if err != nil {
		return nil, fmt.Errorf("LDAP search failed: %v", err)
	}

	if len(sr.Entries) == 0 {
		return nil, fmt.Errorf("target not found: %s", targetDN)
	}

	return ra.analyzeRBCDTarget(sr.Entries[0])
}

// DetectSuspiciousRBCDValues detects suspicious RBCD configurations
func (ra *RBCDAnalyzer) DetectSuspiciousRBCDValues(results []*RBCDResult) []string {
	var suspicious []string

	for _, result := range results {
		// Check for wildcard SIDs
		for _, allowed := range result.AllowedToActOn {
			if strings.Contains(allowed, "*") || strings.Contains(allowed, "S-1-1-0") {
				suspicious = append(suspicious, fmt.Sprintf("Wildcard SID in RBCD for %s: %s", result.TargetName, allowed))
			}
		}

		// Check for high-privilege accounts
		for _, allowed := range result.AllowedToActOn {
			if ra.isHighPrivilegeSID(allowed) {
				suspicious = append(suspicious, fmt.Sprintf("High-privilege account in RBCD for %s: %s", result.TargetName, allowed))
			}
		}

		// Check for unusual SPN configurations
		if len(result.ServicePrincipalNames) > 5 {
			suspicious = append(suspicious, fmt.Sprintf("Unusual number of SPNs for %s: %d", result.TargetName, len(result.ServicePrincipalNames)))
		}

		// Check for high exploitability score
		if result.ExploitabilityScore > 80 {
			suspicious = append(suspicious, fmt.Sprintf("High exploitability score for %s: %d", result.TargetName, result.ExploitabilityScore))
		}
	}

	return suspicious
}

// GenerateExploitationReport generates a report of potential exploitation paths
func (ra *RBCDAnalyzer) GenerateExploitationReport(results []*RBCDResult) map[string]interface{} {
	report := make(map[string]interface{})

	// Count by risk level
	riskCounts := make(map[string]int)
	for _, result := range results {
		riskCounts[result.RiskLevel]++
	}

	report["risk_distribution"] = riskCounts
	report["total_targets"] = len(results)

	// High-risk targets
	var highRisk []*RBCDResult
	for _, result := range results {
		if result.RiskLevel == "High" {
			highRisk = append(highRisk, result)
		}
	}
	report["high_risk_targets"] = highRisk

	// Exploitation paths
	var allPaths []string
	for _, result := range results {
		allPaths = append(allPaths, result.ExploitationPath...)
	}
	report["exploitation_paths"] = allPaths

	// Recommendations
	var allRecommendations []string
	for _, result := range results {
		allRecommendations = append(allRecommendations, result.Recommendations...)
	}
	report["recommendations"] = allRecommendations

	return report
}

// Helper functions

func (ra *RBCDAnalyzer) analyzeRBCDTarget(entry *ldap.Entry) (*RBCDResult, error) {
	result := &RBCDResult{
		TargetDN:              entry.DN,
		TargetName:            entry.GetAttributeValue("sAMAccountName"),
		AllowedToActOn:        entry.GetAttributeValues("msDS-AllowedToActOnBehalfOfOtherIdentity"),
		ServicePrincipalNames: entry.GetAttributeValues("servicePrincipalName"),
	}

	// Calculate exploitability score
	result.ExploitabilityScore = ra.calculateExploitabilityScore(result)

	// Determine risk level
	result.RiskLevel = ra.determineRiskLevel(result.ExploitabilityScore)

	// Generate exploitation path
	result.ExploitationPath = ra.generateExploitationPath(result)

	// Generate recommendations
	result.Recommendations = ra.generateRecommendations(result)

	return result, nil
}

func (ra *RBCDAnalyzer) calculateExploitabilityScore(result *RBCDResult) int {
	score := 0

	// Base score for having RBCD configured
	score += 20

	// Add score based on number of allowed accounts
	score += len(result.AllowedToActOn) * 10

	// Add score for SPNs
	score += len(result.ServicePrincipalNames) * 5

	// Check for high-privilege accounts
	for _, allowed := range result.AllowedToActOn {
		if ra.isHighPrivilegeSID(allowed) {
			score += 30
		}
	}

	// Check for wildcard SIDs
	for _, allowed := range result.AllowedToActOn {
		if strings.Contains(allowed, "*") || strings.Contains(allowed, "S-1-1-0") {
			score += 50
		}
	}

	// Cap at 100
	if score > 100 {
		score = 100
	}

	return score
}

func (ra *RBCDAnalyzer) determineRiskLevel(score int) string {
	if score >= 80 {
		return "High"
	} else if score >= 50 {
		return "Medium"
	}
	return "Low"
}

func (ra *RBCDAnalyzer) generateExploitationPath(result *RBCDResult) []string {
	var path []string

	if len(result.AllowedToActOn) == 0 {
		return []string{"No exploitation path - no accounts allowed to act on behalf"}
	}

	path = append(path, fmt.Sprintf("1. Compromise account with RBCD rights to %s", result.TargetName))
	path = append(path, fmt.Sprintf("2. Use S4U2Self to obtain TGT for target account"))
	path = append(path, fmt.Sprintf("3. Use S4U2Proxy to impersonate any user to %s", result.TargetName))

	if len(result.ServicePrincipalNames) > 0 {
		path = append(path, fmt.Sprintf("4. Access services: %s", strings.Join(result.ServicePrincipalNames, ", ")))
	}

	return path
}

func (ra *RBCDAnalyzer) generateRecommendations(result *RBCDResult) []string {
	var recommendations []string

	if result.RiskLevel == "High" {
		recommendations = append(recommendations, "URGENT: Review and restrict RBCD configuration")
		recommendations = append(recommendations, "Remove unnecessary accounts from msDS-AllowedToActOnBehalfOfOtherIdentity")
	}

	if len(result.AllowedToActOn) > 3 {
		recommendations = append(recommendations, "Consider reducing number of accounts with RBCD rights")
	}

	for _, allowed := range result.AllowedToActOn {
		if strings.Contains(allowed, "*") || strings.Contains(allowed, "S-1-1-0") {
			recommendations = append(recommendations, "CRITICAL: Remove wildcard SIDs from RBCD configuration")
		}
	}

	if len(result.ServicePrincipalNames) > 5 {
		recommendations = append(recommendations, "Review SPN configuration - consider using Managed Service Accounts")
	}

	recommendations = append(recommendations, "Implement monitoring for RBCD-related events")
	recommendations = append(recommendations, "Regular audit of delegation configurations")

	return recommendations
}

func (ra *RBCDAnalyzer) isHighPrivilegeSID(sid string) bool {
	// Check for common high-privilege SIDs
	highPrivilegeSIDs := []string{
		"S-1-5-32-544", // Administrators
		"S-1-5-32-548", // Account Operators
		"S-1-5-32-549", // Server Operators
		"S-1-5-32-550", // Print Operators
		"S-1-5-32-551", // Backup Operators
		"S-1-5-21",     // Domain SIDs (partial match)
	}

	for _, privSID := range highPrivilegeSIDs {
		if strings.Contains(sid, privSID) {
			return true
		}
	}

	return false
}

// AuditRBCDConfiguration provides audit-only analysis without exploitation
func (ra *RBCDAnalyzer) AuditRBCDConfiguration(targetDN string) (map[string]interface{}, error) {
	if !ra.AuditMode {
		return nil, fmt.Errorf("audit mode not enabled")
	}

	log.Printf("🔍 Auditing RBCD configuration for: %s", targetDN)

	result, err := ra.AnalyzeSpecificTarget(targetDN)
	if err != nil {
		return nil, err
	}

	audit := make(map[string]interface{})
	audit["target"] = result.TargetName
	audit["target_dn"] = result.TargetDN
	audit["exploitability_score"] = result.ExploitabilityScore
	audit["risk_level"] = result.RiskLevel
	audit["allowed_accounts"] = result.AllowedToActOn
	audit["service_principal_names"] = result.ServicePrincipalNames
	audit["exploitation_path"] = result.ExploitationPath
	audit["recommendations"] = result.Recommendations
	audit["audit_timestamp"] = "2024-01-01T00:00:00Z" // Would use actual timestamp

	return audit, nil
}
