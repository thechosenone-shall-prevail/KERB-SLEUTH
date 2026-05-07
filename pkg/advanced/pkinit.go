package advanced

import (
	"fmt"
	"log"
	"strings"

	"github.com/go-ldap/ldap/v3"
	"github.com/thechosenone-shall-prevail/cold-relay/pkg/krb"
)

// PKINITResult represents PKINIT/AD CS analysis results
type PKINITResult struct {
	TemplateName       string
	TemplateDN         string
	EnrollmentRights   []string
	Autoenrollment     bool
	SmartCardLogon     bool
	RiskScore          int
	RiskLevel          string
	Exploitability     []string
	ESCVulnerabilities []string
	ESC1               bool
	ESC2               bool
	ESC3               bool
	ESC4               bool
	ESC5               bool
	ESC6               bool
	ESC7               bool
	ESC8               bool
	ESC9               bool
	ESC10              bool
	ESC11              bool
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
	log.Printf("[*] Enumerating AD CS templates...")

	// Check if client is available
	if pa.Client == nil || pa.Client.GetConnection() == nil {
		log.Printf("[!] LDAP client not available, returning empty results")
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
		"msPKI-Cert-Template-OID",
		"msPKI-Enrollment-Auto-Add",
		"msPKI-RA-Signature",
		"msPKI-Template-Schema-Version",
		"msPKI-Certificate-Name-Flag",
		"msPKI-Private-Key-Flag",
		"msPKI-Certificate-Application-Policy",
		"msPKI-RA-Application-Policies",
	}

	entries, err := pa.Client.SearchSubtreePaged(searchFilter, attributes, 500)
	if err != nil {
		return nil, fmt.Errorf("LDAP search failed: %v", err)
	}

	log.Printf("Found %d certificate templates", len(entries))

	var results []*PKINITResult
	for _, entry := range entries {
		result, err := pa.analyzeTemplate(entry)
		if err != nil {
			log.Printf("[x] Failed to analyze template %s: %v", entry.DN, err)
			continue
		}
		results = append(results, result)
	}

	return results, nil
}

// AnalyzeTemplateRisk analyzes risk for specific certificate template
func (pa *PKINITAnalyzer) AnalyzeTemplateRisk(templateName string) (*PKINITResult, error) {
	log.Printf("[*] Analyzing certificate template risk: %s", templateName)

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
		TemplateName:       entry.GetAttributeValue("name"),
		TemplateDN:         entry.DN,
		EnrollmentRights:   entry.GetAttributeValues("pKIEnrollmentAccess"),
		Exploitability:     []string{},
		ESCVulnerabilities: []string{},
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

	// Detect ESC vulnerabilities
	pa.detectESCVulnerabilities(entry, result)

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

	// ESC vulnerabilities significantly increase risk
	escCount := 0
	if result.ESC1 {
		score += 35
		escCount++
	}
	if result.ESC2 {
		score += 30
		escCount++
	}
	if result.ESC3 {
		score += 25
		escCount++
	}
	if result.ESC4 {
		score += 20
		escCount++
	}
	if result.ESC5 {
		score += 15
		escCount++
	}
	if result.ESC6 {
		score += 15
		escCount++
	}
	if result.ESC7 {
		score += 15
		escCount++
	}
	if result.ESC8 {
		score += 20
		escCount++
	}
	if result.ESC9 {
		score += 25
		escCount++
	}
	if result.ESC10 {
		score += 25
		escCount++
	}
	if result.ESC11 {
		score += 30
		escCount++
	}

	// Multiple ESC vulnerabilities increase risk exponentially
	if escCount >= 3 {
		score += 20
	}
	if escCount >= 5 {
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

// detectESCVulnerabilities detects ESC1-ESC11 vulnerabilities in certificate templates
func (pa *PKINITAnalyzer) detectESCVulnerabilities(entry *ldap.Entry, result *PKINITResult) {
	// ESC1: Template allows enrollment by low-privileged users and has dangerous EKUs
	enrollRights := entry.GetAttributeValues("pKIEnrollmentAccess")
	extendedKeyUsage := entry.GetAttributeValues("pKIExtendedKeyUsage")

	hasDangerousEKU := false
	for _, eku := range extendedKeyUsage {
		lowerEKU := strings.ToLower(eku)
		if strings.Contains(lowerEKU, "client authentication") ||
			strings.Contains(lowerEKU, "1.3.6.1.5.5.7.3.2") {
			hasDangerousEKU = true
			break
		}
	}

	hasAnyEnroll := len(enrollRights) > 0
	if hasAnyEnroll && hasDangerousEKU {
		result.ESC1 = true
		result.ESCVulnerabilities = append(result.ESCVulnerabilities, "ESC1: Template allows enrollment with Client Authentication EKU")
	}

	// ESC2: Template allows any purpose EKU
	for _, eku := range extendedKeyUsage {
		if strings.Contains(eku, "Any Purpose") || strings.Contains(eku, "2.5.29.37.0") {
			result.ESC2 = true
			result.ESCVulnerabilities = append(result.ESCVulnerabilities, "ESC2: Template allows Any Purpose EKU")
			break
		}
	}

	// ESC3: Template allows enrollment for certificate request agents
	for _, eku := range extendedKeyUsage {
		if strings.Contains(eku, "Certificate Request Agent") || strings.Contains(eku, "1.3.6.1.4.1.311.21.6") {
			result.ESC3 = true
			result.ESCVulnerabilities = append(result.ESCVulnerabilities, "ESC3: Template allows Certificate Request Agent EKU")
			break
		}
	}

	// ESC4: Template allows enrollment by low-privileged users and has no manager approval
	autoAdd := entry.GetAttributeValue("msPKI-Enrollment-Auto-Add")
	if hasAnyEnroll && autoAdd == "1" {
		result.ESC4 = true
		result.ESCVulnerabilities = append(result.ESCVulnerabilities, "ESC4: Template allows enrollment without manager approval")
	}

	// ESC5: Vulnerable PKI object (CA configuration)
	// This requires checking the CA's msPKI-Enrollment-Servers attribute
	// Simplified check - would need CA access for full detection
	if strings.Contains(strings.ToLower(result.TemplateName), "ca") ||
		strings.Contains(strings.ToLower(result.TemplateName), "subca") {
		result.ESC5 = true
		result.ESCVulnerabilities = append(result.ESCVulnerabilities, "ESC5: Potential CA configuration vulnerability (requires CA access)")
	}

	// ESC6: EDITF_ATTRIBUTESUBJECTALTNAME2 flag set on CA
	// This requires CA access - flagging as potential
	if strings.Contains(strings.ToLower(result.TemplateName), "user") ||
		strings.Contains(strings.ToLower(result.TemplateName), "machine") {
		result.ESC6 = true
		result.ESCVulnerabilities = append(result.ESCVulnerabilities, "ESC6: Potential EDITF_ATTRIBUTESUBJECTALTNAME2 vulnerability (requires CA access)")
	}

	// ESC7: Request Disallowed flag set but vulnerable to renewal abuse
	// This requires checking CA flags - flagging as potential
	if strings.Contains(strings.ToLower(result.TemplateName), "enrollment") {
		result.ESC7 = true
		result.ESCVulnerabilities = append(result.ESCVulnerabilities, "ESC7: Potential Request Disallowed vulnerability (requires CA access)")
	}

	// ESC8: Vulnerable to renewal abuse if template allows renewal
	// Check for renewal flags
	certNameFlag := entry.GetAttributeValue("msPKI-Certificate-Name-Flag")
	if strings.Contains(certNameFlag, "1") || strings.Contains(certNameFlag, "ENROLLEE_SUPPLIES_SUBJECT") {
		result.ESC8 = true
		result.ESCVulnerabilities = append(result.ESCVulnerabilities, "ESC8: Template allows subject name supply (potential renewal abuse)")
	}

	// ESC9: Vulnerable to PKINIT pre-auth bypass
	// Check for SmartCardLogon with no strong mapping requirement
	if result.SmartCardLogon {
		result.ESC9 = true
		result.ESCVulnerabilities = append(result.ESCVulnerabilities, "ESC9: Template allows SmartCardLogon (potential PKINIT pre-auth bypass)")
	}

	// ESC10: Vulnerable to shadow credentials abuse
	// Check if template allows enrollment with subject alternative name
	if hasAnyEnroll && strings.Contains(certNameFlag, "1") {
		result.ESC10 = true
		result.ESCVulnerabilities = append(result.ESCVulnerabilities, "ESC10: Template allows SAN manipulation (potential shadow credentials abuse)")
	}

	// ESC11: Vulnerable to NTLM relay to CA
	// Check if template allows authentication and has no strong binding
	if hasDangerousEKU && hasAnyEnroll {
		result.ESC11 = true
		result.ESCVulnerabilities = append(result.ESCVulnerabilities, "ESC11: Template allows authentication (potential NTLM relay to CA)")
	}
}
