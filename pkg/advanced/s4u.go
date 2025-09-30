package advanced

import (
	"fmt"
	"log"
	"strings"

	"github.com/go-ldap/ldap/v3"
	"github.com/thechosenone-shall-prevail/KERB-SLEUTH/pkg/krb"
)

// S4UResult represents S4U delegation analysis results
type S4UResult struct {
	AccountDN             string
	AccountName           string
	DelegationType        string // "S4U2Self", "S4U2Proxy", "Constrained", "Unconstrained"
	TrustedForDelegation  bool
	AllowedToActOn        []string
	ServicePrincipalNames []string
	ExploitabilityScore   int
	RiskLevel             string
	DelegationFlags       []string
	ExploitationPath      []string
}

// S4UAnalyzer handles S4U delegation enumeration and analysis
type S4UAnalyzer struct {
	Client    *krb.LDAPClient
	AuditMode bool
}

// NewS4UAnalyzer creates a new S4U analyzer
func NewS4UAnalyzer(client *krb.LDAPClient, auditMode bool) *S4UAnalyzer {
	return &S4UAnalyzer{
		Client:    client,
		AuditMode: auditMode,
	}
}

// EnumerateS4UDelegation enumerates all accounts with S4U delegation configurations
func (sa *S4UAnalyzer) EnumerateS4UDelegation() ([]*S4UResult, error) {
	log.Printf("[*] Enumerating S4U delegation configurations...")

	// Check if client is available
	if sa.Client == nil || sa.Client.GetConnection() == nil {
		log.Printf("[!] LDAP client not available, returning empty results")
		return []*S4UResult{}, nil
	}

	// Search for accounts with delegation flags
	searchFilter := "(|(trustedForDelegation=TRUE)(msDS-AllowedToActOnBehalfOfOtherIdentity=*)(msDS-AllowedToDelegateTo=*))"
	attributes := []string{
		"distinguishedName",
		"sAMAccountName",
		"trustedForDelegation",
		"msDS-AllowedToActOnBehalfOfOtherIdentity",
		"msDS-AllowedToDelegateTo",
		"servicePrincipalName",
		"userAccountControl",
		"objectClass",
	}

	searchRequest := ldap.NewSearchRequest(
		sa.Client.GetBaseDN(),
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, 0, false,
		searchFilter,
		attributes,
		nil,
	)

	sr, err := sa.Client.GetConnection().Search(searchRequest)
	if err != nil {
		return nil, fmt.Errorf("LDAP search failed: %v", err)
	}

	log.Printf("Found %d accounts with S4U delegation configurations", len(sr.Entries))

	var results []*S4UResult
	for _, entry := range sr.Entries {
		result, err := sa.analyzeS4UAccount(entry)
		if err != nil {
			log.Printf("[x] Failed to analyze S4U account %s: %v", entry.DN, err)
			continue
		}
		results = append(results, result)
	}

	return results, nil
}

// SimulateS4URequest simulates S4U2Self/S4U2Proxy requests (audit mode only)
func (sa *S4UAnalyzer) SimulateS4URequest(targetAccount, impersonateUser string) (*S4UResult, error) {
	if !sa.AuditMode {
		return nil, fmt.Errorf("S4U simulation requires audit mode")
	}

	log.Printf("[*] Simulating S4U request for %s to impersonate %s", targetAccount, impersonateUser)

	// Find the target account
	result, err := sa.findAccountBySamAccountName(targetAccount)
	if err != nil {
		return nil, fmt.Errorf("failed to find target account: %v", err)
	}

	// Simulate S4U2Self request
	if result.TrustedForDelegation {
		log.Printf("[+] S4U2Self simulation: %s can obtain TGT for %s", targetAccount, impersonateUser)
		result.DelegationFlags = append(result.DelegationFlags, "S4U2Self_SUCCESS")
	} else {
		log.Printf("[!] S4U2Self simulation: %s cannot obtain TGT for %s", targetAccount, impersonateUser)
		result.DelegationFlags = append(result.DelegationFlags, "S4U2Self_FAILED")
	}

	// Simulate S4U2Proxy request
	if len(result.AllowedToActOn) > 0 {
		log.Printf("[+] S4U2Proxy simulation: %s can impersonate %s to delegated services", targetAccount, impersonateUser)
		result.DelegationFlags = append(result.DelegationFlags, "S4U2Proxy_SUCCESS")
	} else {
		log.Printf("[!] S4U2Proxy simulation: %s cannot impersonate %s to delegated services", targetAccount, impersonateUser)
		result.DelegationFlags = append(result.DelegationFlags, "S4U2Proxy_FAILED")
	}

	// Update exploitability score
	result.ExploitabilityScore = sa.calculateS4UExploitabilityScore(result)
	result.RiskLevel = sa.determineS4URiskLevel(result.ExploitabilityScore)

	return result, nil
}

// DetectS4UAbusePatterns detects patterns indicating S4U abuse
func (sa *S4UAnalyzer) DetectS4UAbusePatterns(results []*S4UResult) []string {
	var patterns []string

	for _, result := range results {
		// Check for unconstrained delegation
		if result.DelegationType == "Unconstrained" {
			patterns = append(patterns, fmt.Sprintf("Unconstrained delegation enabled for %s", result.AccountName))
		}

		// Check for high-privilege accounts with delegation
		if sa.isHighPrivilegeAccount(result.AccountName) && result.TrustedForDelegation {
			patterns = append(patterns, fmt.Sprintf("High-privilege account %s has delegation enabled", result.AccountName))
		}

		// Check for unusual delegation configurations
		if len(result.AllowedToActOn) > 10 {
			patterns = append(patterns, fmt.Sprintf("Unusual number of delegation targets for %s: %d", result.AccountName, len(result.AllowedToActOn)))
		}

		// Check for high exploitability score
		if result.ExploitabilityScore > 80 {
			patterns = append(patterns, fmt.Sprintf("High S4U exploitability score for %s: %d", result.AccountName, result.ExploitabilityScore))
		}
	}

	return patterns
}

// GenerateS4UReport generates a comprehensive S4U delegation report
func (sa *S4UAnalyzer) GenerateS4UReport(results []*S4UResult) map[string]interface{} {
	report := make(map[string]interface{})

	// Count by delegation type
	typeCounts := make(map[string]int)
	for _, result := range results {
		typeCounts[result.DelegationType]++
	}
	report["delegation_types"] = typeCounts

	// Count by risk level
	riskCounts := make(map[string]int)
	for _, result := range results {
		riskCounts[result.RiskLevel]++
	}
	report["risk_distribution"] = riskCounts

	// High-risk accounts
	var highRisk []*S4UResult
	for _, result := range results {
		if result.RiskLevel == "High" {
			highRisk = append(highRisk, result)
		}
	}
	report["high_risk_accounts"] = highRisk

	// Unconstrained delegation accounts
	var unconstrained []*S4UResult
	for _, result := range results {
		if result.DelegationType == "Unconstrained" {
			unconstrained = append(unconstrained, result)
		}
	}
	report["unconstrained_delegation"] = unconstrained

	// Exploitation paths
	var allPaths []string
	for _, result := range results {
		allPaths = append(allPaths, result.ExploitationPath...)
	}
	report["exploitation_paths"] = allPaths

	return report
}

// Helper functions

func (sa *S4UAnalyzer) analyzeS4UAccount(entry *ldap.Entry) (*S4UResult, error) {
	result := &S4UResult{
		AccountDN:             entry.DN,
		AccountName:           entry.GetAttributeValue("sAMAccountName"),
		TrustedForDelegation:  entry.GetAttributeValue("trustedForDelegation") == "TRUE",
		AllowedToActOn:        entry.GetAttributeValues("msDS-AllowedToActOnBehalfOfOtherIdentity"),
		ServicePrincipalNames: entry.GetAttributeValues("servicePrincipalName"),
	}

	// Determine delegation type
	result.DelegationType = sa.determineDelegationType(result)

	// Calculate exploitability score
	result.ExploitabilityScore = sa.calculateS4UExploitabilityScore(result)

	// Determine risk level
	result.RiskLevel = sa.determineS4URiskLevel(result.ExploitabilityScore)

	// Generate exploitation path
	result.ExploitationPath = sa.generateS4UExploitationPath(result)

	return result, nil
}

func (sa *S4UAnalyzer) determineDelegationType(result *S4UResult) string {
	if result.TrustedForDelegation && len(result.AllowedToActOn) == 0 {
		return "Unconstrained"
	} else if result.TrustedForDelegation && len(result.AllowedToActOn) > 0 {
		return "Constrained"
	} else if len(result.AllowedToActOn) > 0 {
		return "S4U2Proxy"
	} else if result.TrustedForDelegation {
		return "S4U2Self"
	}
	return "None"
}

func (sa *S4UAnalyzer) calculateS4UExploitabilityScore(result *S4UResult) int {
	score := 0

	// Base score for having delegation enabled
	if result.TrustedForDelegation {
		score += 30
	}

	// Add score for constrained delegation
	if len(result.AllowedToActOn) > 0 {
		score += 20
	}

	// Add score for SPNs
	score += len(result.ServicePrincipalNames) * 5

	// Unconstrained delegation is very dangerous
	if result.DelegationType == "Unconstrained" {
		score += 40
	}

	// Check for high-privilege accounts
	if sa.isHighPrivilegeAccount(result.AccountName) {
		score += 25
	}

	// Cap at 100
	if score > 100 {
		score = 100
	}

	return score
}

func (sa *S4UAnalyzer) determineS4URiskLevel(score int) string {
	if score >= 80 {
		return "High"
	} else if score >= 50 {
		return "Medium"
	}
	return "Low"
}

func (sa *S4UAnalyzer) generateS4UExploitationPath(result *S4UResult) []string {
	var path []string

	if !result.TrustedForDelegation && len(result.AllowedToActOn) == 0 {
		return []string{"No exploitation path - no delegation configured"}
	}

	if result.TrustedForDelegation {
		path = append(path, fmt.Sprintf("1. Compromise account %s with S4U2Self rights", result.AccountName))
		path = append(path, "2. Use S4U2Self to obtain TGT for any user")
	}

	if len(result.AllowedToActOn) > 0 {
		path = append(path, fmt.Sprintf("3. Use S4U2Proxy to impersonate users to: %s", strings.Join(result.AllowedToActOn, ", ")))
	}

	if len(result.ServicePrincipalNames) > 0 {
		path = append(path, fmt.Sprintf("4. Access services: %s", strings.Join(result.ServicePrincipalNames, ", ")))
	}

	return path
}

func (sa *S4UAnalyzer) isHighPrivilegeAccount(accountName string) bool {
	// Check for common high-privilege account patterns
	highPrivilegePatterns := []string{
		"admin",
		"administrator",
		"service",
		"svc",
		"sql",
		"exchange",
		"backup",
		"root",
	}

	accountLower := strings.ToLower(accountName)
	for _, pattern := range highPrivilegePatterns {
		if strings.Contains(accountLower, pattern) {
			return true
		}
	}

	return false
}

func (sa *S4UAnalyzer) findAccountBySamAccountName(samAccountName string) (*S4UResult, error) {
	searchFilter := fmt.Sprintf("(sAMAccountName=%s)", samAccountName)
	attributes := []string{
		"distinguishedName",
		"sAMAccountName",
		"trustedForDelegation",
		"msDS-AllowedToActOnBehalfOfOtherIdentity",
		"msDS-AllowedToDelegateTo",
		"servicePrincipalName",
		"userAccountControl",
		"objectClass",
	}

	searchRequest := ldap.NewSearchRequest(
		sa.Client.GetBaseDN(),
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, 0, false,
		searchFilter,
		attributes,
		nil,
	)

	sr, err := sa.Client.GetConnection().Search(searchRequest)
	if err != nil {
		return nil, fmt.Errorf("LDAP search failed: %v", err)
	}

	if len(sr.Entries) == 0 {
		return nil, fmt.Errorf("account not found: %s", samAccountName)
	}

	return sa.analyzeS4UAccount(sr.Entries[0])
}

// AuditS4UConfiguration provides audit-only analysis of S4U delegation
func (sa *S4UAnalyzer) AuditS4UConfiguration(targetAccount string) (map[string]interface{}, error) {
	if !sa.AuditMode {
		return nil, fmt.Errorf("audit mode not enabled")
	}

	log.Printf("🔍 Auditing S4U configuration for: %s", targetAccount)

	result, err := sa.findAccountBySamAccountName(targetAccount)
	if err != nil {
		return nil, err
	}

	audit := make(map[string]interface{})
	audit["account"] = result.AccountName
	audit["account_dn"] = result.AccountDN
	audit["delegation_type"] = result.DelegationType
	audit["trusted_for_delegation"] = result.TrustedForDelegation
	audit["allowed_to_act_on"] = result.AllowedToActOn
	audit["service_principal_names"] = result.ServicePrincipalNames
	audit["exploitability_score"] = result.ExploitabilityScore
	audit["risk_level"] = result.RiskLevel
	audit["delegation_flags"] = result.DelegationFlags
	audit["exploitation_path"] = result.ExploitationPath
	audit["audit_timestamp"] = "2024-01-01T00:00:00Z" // Would use actual timestamp

	return audit, nil
}
