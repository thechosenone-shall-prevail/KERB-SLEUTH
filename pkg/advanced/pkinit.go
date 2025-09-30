package advanced

import (
	"fmt"
	"log"
	"strings"

	"github.com/go-ldap/ldap/v3"
	"github.com/thechosenone-shall-prevail/KERB-SLEUTH/pkg/krb"
)

// PKINITResult represents PKINIT/AD CS analysis results
type PKINITResult struct {
	TemplateName     string
	TemplateDN       string
	EnrollmentRights []string
	Autoenrollment   bool
	SmartCardLogon   bool
	RiskScore        int
	RiskLevel        string
	Exploitability   []string
}

// PKINITAnalyzer handles PKINIT/AD CS enumeration and analysis
type PKINITAnalyzer struct {
	Client    *krb.LDAPClient
	AuditMode bool
}

// NewPKINITAnalyzer creates a new PKINIT analyzer
func NewPKINITAnalyzer(client *krb.LDAPClient, auditMode bool) *PKINITAnalyzer {
	return &PKINITAnalyzer{
		Client:    client,
		AuditMode: auditMode,
	}
}

// EnumerateADCS enumerates AD Certificate Services templates
func (pa *PKINITAnalyzer) EnumerateADCS() ([]*PKINITResult, error) {
	log.Printf("🔍 Enumerating AD CS templates...")

	// Check if client is available
	if pa.Client == nil || pa.Client.GetConnection() == nil {
		log.Printf("⚠️  LDAP client not available, returning empty results")
		return []*PKINITResult{}, nil
	}

	// Search for certificate templates
	searchFilter := "(objectClass=pKICertificateTemplate)"
	attributes := []string{
		"distinguishedName",
		"name",
		"pKIEnrollmentAccess",
		"pKIAutoEnrollmentFlags",
		"pKIExtendedKeyUsage",
		"pKIKeyUsage",
	}

	searchRequest := ldap.NewSearchRequest(
		pa.Client.GetBaseDN(),
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, 0, false,
		searchFilter,
		attributes,
		nil,
	)

	sr, err := pa.Client.GetConnection().Search(searchRequest)
	if err != nil {
		return nil, fmt.Errorf("LDAP search failed: %v", err)
	}

	log.Printf("Found %d certificate templates", len(sr.Entries))

	var results []*PKINITResult
	for _, entry := range sr.Entries {
		result, err := pa.analyzeTemplate(entry)
		if err != nil {
			log.Printf("⚠️  Failed to analyze template %s: %v", entry.DN, err)
			continue
		}
		results = append(results, result)
	}

	return results, nil
}

// AnalyzeTemplateRisk analyzes risk for specific certificate template
func (pa *PKINITAnalyzer) AnalyzeTemplateRisk(templateName string) (*PKINITResult, error) {
	log.Printf("🎯 Analyzing certificate template risk: %s", templateName)

	searchFilter := fmt.Sprintf("(name=%s)", templateName)
	searchRequest := ldap.NewSearchRequest(
		pa.Client.GetBaseDN(),
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, 0, false,
		searchFilter,
		[]string{"distinguishedName", "name", "pKIEnrollmentAccess", "pKIAutoEnrollmentFlags"},
		nil,
	)

	sr, err := pa.Client.GetConnection().Search(searchRequest)
	if err != nil {
		return nil, fmt.Errorf("LDAP search failed: %v", err)
	}

	if len(sr.Entries) == 0 {
		return nil, fmt.Errorf("template not found: %s", templateName)
	}

	return pa.analyzeTemplate(sr.Entries[0])
}

// DetectPKINITAbuse detects potential PKINIT abuse patterns
func (pa *PKINITAnalyzer) DetectPKINITAbuse(results []*PKINITResult) []string {
	var patterns []string

	for _, result := range results {
		if result.RiskScore > 80 {
			patterns = append(patterns, fmt.Sprintf("High-risk certificate template: %s (score: %d)", result.TemplateName, result.RiskScore))
		}

		if result.Autoenrollment {
			patterns = append(patterns, fmt.Sprintf("Autoenrollment enabled for template: %s", result.TemplateName))
		}

		if result.SmartCardLogon {
			patterns = append(patterns, fmt.Sprintf("SmartCardLogon enabled for template: %s", result.TemplateName))
		}

		if len(result.EnrollmentRights) > 10 {
			patterns = append(patterns, fmt.Sprintf("Excessive enrollment rights for template: %s (%d accounts)", result.TemplateName, len(result.EnrollmentRights)))
		}
	}

	return patterns
}

// Helper functions

func (pa *PKINITAnalyzer) analyzeTemplate(entry *ldap.Entry) (*PKINITResult, error) {
	result := &PKINITResult{
		TemplateName:     entry.GetAttributeValue("name"),
		TemplateDN:       entry.DN,
		EnrollmentRights: entry.GetAttributeValues("pKIEnrollmentAccess"),
		Exploitability:   []string{},
	}

	// Check autoenrollment flags
	autoenrollFlags := entry.GetAttributeValue("pKIAutoEnrollmentFlags")
	result.Autoenrollment = strings.Contains(autoenrollFlags, "1")

	// Check for SmartCardLogon
	extendedKeyUsage := entry.GetAttributeValues("pKIExtendedKeyUsage")
	for _, usage := range extendedKeyUsage {
		if strings.Contains(usage, "SmartCardLogon") {
			result.SmartCardLogon = true
			break
		}
	}

	// Calculate risk score
	result.RiskScore = pa.calculateRiskScore(result)

	// Determine risk level
	result.RiskLevel = pa.determineRiskLevel(result.RiskScore)

	// Generate exploitability paths
	result.Exploitability = pa.generateExploitabilityPaths(result)

	return result, nil
}

func (pa *PKINITAnalyzer) calculateRiskScore(result *PKINITResult) int {
	score := 0

	// Base score for having enrollment rights
	score += len(result.EnrollmentRights) * 5

	// Autoenrollment increases risk
	if result.Autoenrollment {
		score += 30
	}

	// SmartCardLogon increases risk
	if result.SmartCardLogon {
		score += 25
	}

	// Check for high-privilege templates
	if strings.Contains(strings.ToLower(result.TemplateName), "admin") ||
		strings.Contains(strings.ToLower(result.TemplateName), "domain") {
		score += 20
	}

	// Cap at 100
	if score > 100 {
		score = 100
	}

	return score
}

func (pa *PKINITAnalyzer) determineRiskLevel(score int) string {
	if score >= 80 {
		return "High"
	} else if score >= 50 {
		return "Medium"
	}
	return "Low"
}

func (pa *PKINITAnalyzer) generateExploitabilityPaths(result *PKINITResult) []string {
	var paths []string

	if result.Autoenrollment {
		paths = append(paths, fmt.Sprintf("Autoenrollment abuse via template: %s", result.TemplateName))
	}

	if result.SmartCardLogon {
		paths = append(paths, fmt.Sprintf("SmartCardLogon abuse via template: %s", result.TemplateName))
	}

	if len(result.EnrollmentRights) > 0 {
		paths = append(paths, fmt.Sprintf("Certificate enrollment abuse via template: %s", result.TemplateName))
	}

	return paths
}
