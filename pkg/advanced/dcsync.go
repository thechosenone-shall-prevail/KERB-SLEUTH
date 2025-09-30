package advanced

import (
	"fmt"
	"log"
	"strings"

	"github.com/go-ldap/ldap/v3"
	"github.com/thechosenone-shall-prevail/KERB-SLEUTH/pkg/krb"
)

// DCSyncResult represents DCSync enumeration results
type DCSyncResult struct {
	AccountDN           string
	AccountName         string
	ReplicationRights   []string
	ExploitabilityScore int
	RiskLevel           string
	ExploitationPath    []string
	Recommendations     []string
}

// DCSyncAnalyzer handles DCSync enumeration and analysis
type DCSyncAnalyzer struct {
	Client    *krb.LDAPClient
	AuditMode bool
}

// NewDCSyncAnalyzer creates a new DCSync analyzer
func NewDCSyncAnalyzer(client *krb.LDAPClient, auditMode bool) *DCSyncAnalyzer {
	return &DCSyncAnalyzer{
		Client:    client,
		AuditMode: auditMode,
	}
}

// EnumerateReplicationRights enumerates accounts with replication rights
func (da *DCSyncAnalyzer) EnumerateReplicationRights() ([]*DCSyncResult, error) {
	log.Printf("🔍 Enumerating accounts with replication rights...")

	// Check if client is available
	if da.Client == nil || da.Client.GetConnection() == nil {
		log.Printf("⚠️  LDAP client not available, returning empty results")
		return []*DCSyncResult{}, nil
	}

	// Search for accounts with replication rights
	searchFilter := "(|(objectSid=*)(primaryGroupID=*))"
	attributes := []string{
		"distinguishedName",
		"sAMAccountName",
		"memberOf",
		"userAccountControl",
		"objectClass",
	}

	searchRequest := ldap.NewSearchRequest(
		da.Client.GetBaseDN(),
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, 0, false,
		searchFilter,
		attributes,
		nil,
	)

	sr, err := da.Client.GetConnection().Search(searchRequest)
	if err != nil {
		return nil, fmt.Errorf("LDAP search failed: %v", err)
	}

	log.Printf("Found %d accounts to analyze for replication rights", len(sr.Entries))

	var results []*DCSyncResult
	for _, entry := range sr.Entries {
		result, err := da.analyzeReplicationRights(entry)
		if err != nil {
			log.Printf("⚠️  Failed to analyze account %s: %v", entry.DN, err)
			continue
		}
		if len(result.ReplicationRights) > 0 {
			results = append(results, result)
		}
	}

	return results, nil
}

// CheckSpecificAccount checks replication rights for specific account
func (da *DCSyncAnalyzer) CheckSpecificAccount(accountName string) (*DCSyncResult, error) {
	log.Printf("🎯 Checking replication rights for: %s", accountName)

	searchFilter := fmt.Sprintf("(sAMAccountName=%s)", accountName)
	searchRequest := ldap.NewSearchRequest(
		da.Client.GetBaseDN(),
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, 0, false,
		searchFilter,
		[]string{"distinguishedName", "sAMAccountName", "memberOf", "userAccountControl"},
		nil,
	)

	sr, err := da.Client.GetConnection().Search(searchRequest)
	if err != nil {
		return nil, fmt.Errorf("LDAP search failed: %v", err)
	}

	if len(sr.Entries) == 0 {
		return nil, fmt.Errorf("account not found: %s", accountName)
	}

	return da.analyzeReplicationRights(sr.Entries[0])
}

// DetectDCSyncAbuse detects potential DCSync abuse patterns
func (da *DCSyncAnalyzer) DetectDCSyncAbuse(results []*DCSyncResult) []string {
	var patterns []string

	for _, result := range results {
		if result.RiskLevel == "High" {
			patterns = append(patterns, fmt.Sprintf("High-risk replication rights for %s", result.AccountName))
		}

		if da.isHighPrivilegeAccount(result.AccountName) {
			patterns = append(patterns, fmt.Sprintf("High-privilege account %s has replication rights", result.AccountName))
		}

		if len(result.ReplicationRights) > 5 {
			patterns = append(patterns, fmt.Sprintf("Excessive replication rights for %s: %d", result.AccountName, len(result.ReplicationRights)))
		}
	}

	return patterns
}

// GenerateDCSyncReport generates a comprehensive DCSync report
func (da *DCSyncAnalyzer) GenerateDCSyncReport(results []*DCSyncResult) map[string]interface{} {
	report := make(map[string]interface{})

	// Count by risk level
	riskCounts := make(map[string]int)
	for _, result := range results {
		riskCounts[result.RiskLevel]++
	}
	report["risk_distribution"] = riskCounts

	// High-risk accounts
	var highRisk []*DCSyncResult
	for _, result := range results {
		if result.RiskLevel == "High" {
			highRisk = append(highRisk, result)
		}
	}
	report["high_risk_accounts"] = highRisk

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

func (da *DCSyncAnalyzer) analyzeReplicationRights(entry *ldap.Entry) (*DCSyncResult, error) {
	result := &DCSyncResult{
		AccountDN:         entry.DN,
		AccountName:       entry.GetAttributeValue("sAMAccountName"),
		ReplicationRights: []string{},
		ExploitationPath:  []string{},
		Recommendations:   []string{},
	}

	// Check group membership for replication rights
	groups := entry.GetAttributeValues("memberOf")
	for _, group := range groups {
		if da.hasReplicationRights(group) {
			result.ReplicationRights = append(result.ReplicationRights, group)
		}
	}

	// Calculate exploitability score
	result.ExploitabilityScore = da.calculateExploitabilityScore(result)

	// Determine risk level
	result.RiskLevel = da.determineRiskLevel(result.ExploitabilityScore)

	// Generate exploitation path
	result.ExploitationPath = da.generateExploitationPath(result)

	// Generate recommendations
	result.Recommendations = da.generateRecommendations(result)

	return result, nil
}

func (da *DCSyncAnalyzer) hasReplicationRights(groupDN string) bool {
	// Check for common replication groups
	replicationGroups := []string{
		"Replicating Directory Changes",
		"Replicating Directory Changes All",
		"Domain Controllers",
		"Enterprise Read-only Domain Controllers",
		"Read-only Domain Controllers",
	}

	groupLower := strings.ToLower(groupDN)
	for _, repGroup := range replicationGroups {
		if strings.Contains(groupLower, strings.ToLower(repGroup)) {
			return true
		}
	}

	return false
}

func (da *DCSyncAnalyzer) calculateExploitabilityScore(result *DCSyncResult) int {
	score := 0

	// Base score for having replication rights
	score += len(result.ReplicationRights) * 20

	// Check for high-privilege accounts
	if da.isHighPrivilegeAccount(result.AccountName) {
		score += 30
	}

	// Check for specific dangerous groups
	for _, right := range result.ReplicationRights {
		if strings.Contains(strings.ToLower(right), "replicating directory changes all") {
			score += 40
		}
		if strings.Contains(strings.ToLower(right), "domain controllers") {
			score += 25
		}
	}

	// Cap at 100
	if score > 100 {
		score = 100
	}

	return score
}

func (da *DCSyncAnalyzer) determineRiskLevel(score int) string {
	if score >= 80 {
		return "High"
	} else if score >= 50 {
		return "Medium"
	}
	return "Low"
}

func (da *DCSyncAnalyzer) generateExploitationPath(result *DCSyncResult) []string {
	var path []string

	if len(result.ReplicationRights) == 0 {
		return []string{"No exploitation path - no replication rights"}
	}

	path = append(path, fmt.Sprintf("1. Compromise account %s with replication rights", result.AccountName))
	path = append(path, "2. Use DCSync to extract password hashes from domain controllers")
	path = append(path, "3. Use extracted hashes for lateral movement and privilege escalation")

	return path
}

func (da *DCSyncAnalyzer) generateRecommendations(result *DCSyncResult) []string {
	var recommendations []string

	if result.RiskLevel == "High" {
		recommendations = append(recommendations, "URGENT: Review replication rights for this account")
		recommendations = append(recommendations, "Consider removing unnecessary replication rights")
	}

	if da.isHighPrivilegeAccount(result.AccountName) {
		recommendations = append(recommendations, "High-privilege account with replication rights - review necessity")
	}

	recommendations = append(recommendations, "Implement monitoring for DCSync events")
	recommendations = append(recommendations, "Regular audit of replication rights")
	recommendations = append(recommendations, "Use least privilege principle for replication access")

	return recommendations
}

func (da *DCSyncAnalyzer) isHighPrivilegeAccount(accountName string) bool {
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
