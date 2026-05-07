package advanced

import (
	"fmt"
	"log"

	"github.com/go-ldap/ldap/v3"
	"github.com/thechosenone-shall-prevail/cold-relay/pkg/krb"
)

// PasswordPolicyResult represents password policy analysis results
type PasswordPolicyResult struct {
	PolicyType       string   `json:"policy_type"`
	Name             string   `json:"name"`
	MinLength        int      `json:"min_length"`
	MaxLength        int      `json:"max_length"`
	Complexity       bool     `json:"complexity_required"`
	History          int      `json:"password_history"`
	LockoutDuration  int      `json:"lockout_duration_seconds"`
	LockoutThreshold int      `json:"lockout_threshold"`
	MaxAge           int      `json:"max_age_days"`
	MinAge           int      `json:"min_age_days"`
	RiskScore        int      `json:"risk_score"`
	RiskLevel        string   `json:"risk_level"`
	Recommendations  []string `json:"recommendations"`
}

// PasswordPolicyAnalyzer handles password policy analysis
type PasswordPolicyAnalyzer struct {
	Client    *krb.LDAPClient
	AuditMode bool
}

// NewPasswordPolicyAnalyzer creates a new password policy analyzer
func NewPasswordPolicyAnalyzer(client *krb.LDAPClient, auditMode bool) *PasswordPolicyAnalyzer {
	return &PasswordPolicyAnalyzer{
		Client:    client,
		AuditMode: auditMode,
	}
}

// EnumeratePasswordPolicies enumerates password policies and fine-grained password policies
func (ppa *PasswordPolicyAnalyzer) EnumeratePasswordPolicies() ([]*PasswordPolicyResult, error) {
	log.Printf("[*] Starting password policy analysis...")

	// Check if client is available
	if ppa.Client == nil || ppa.Client.GetConnection() == nil {
		log.Printf("[!] LDAP client not available, returning empty results")
		return []*PasswordPolicyResult{}, nil
	}

	var results []*PasswordPolicyResult

	// Get default domain password policy
	defaultPolicy, err := ppa.getDefaultDomainPolicy()
	if err != nil {
		log.Printf("[!] Failed to get default domain policy: %v", err)
	} else {
		results = append(results, defaultPolicy)
	}

	// Get fine-grained password policies (PSOs)
	psos, err := ppa.getFineGrainedPolicies()
	if err != nil {
		log.Printf("[!] Failed to get fine-grained policies: %v", err)
	} else {
		results = append(results, psos...)
	}

	log.Printf("[+] Found %d password policies", len(results))

	return results, nil
}

// getDefaultDomainPolicy retrieves the default domain password policy
func (ppa *PasswordPolicyAnalyzer) getDefaultDomainPolicy() (*PasswordPolicyResult, error) {
	searchRequest := ldap.NewSearchRequest(
		ppa.Client.GetBaseDN(),
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0, 0, false,
		"(objectClass=domain)",
		[]string{
			"minPwdLength",
			"maxPwdLength",
			"pwdProperties",
			"pwdHistoryLength",
			"lockoutDuration",
			"lockoutThreshold",
			"maxPwdAge",
			"minPwdAge",
		},
		nil,
	)

	sr, err := ppa.Client.GetConnection().Search(searchRequest)
	if err != nil {
		return nil, fmt.Errorf("LDAP search failed: %v", err)
	}

	if len(sr.Entries) == 0 {
		return nil, fmt.Errorf("domain object not found")
	}

	entry := sr.Entries[0]
	result := &PasswordPolicyResult{
		PolicyType:      "default_domain_policy",
		Name:            "Default Domain Policy",
		Recommendations: []string{},
	}

	// Parse attributes
	result.MinLength = parseInt(entry.GetAttributeValue("minPwdLength"))
	result.MaxLength = parseInt(entry.GetAttributeValue("maxPwdLength"))
	result.History = parseInt(entry.GetAttributeValue("pwdHistoryLength"))
	result.LockoutDuration = parseInt(entry.GetAttributeValue("lockoutDuration"))
	result.LockoutThreshold = parseInt(entry.GetAttributeValue("lockoutThreshold"))
	result.MaxAge = parseDays(entry.GetAttributeValue("maxPwdAge"))
	result.MinAge = parseDays(entry.GetAttributeValue("minPwdAge"))

	// Check complexity (pwdProperties bit 1)
	pwdProps := parseInt(entry.GetAttributeValue("pwdProperties"))
	result.Complexity = (pwdProps & 0x1) != 0

	// Calculate risk score
	result.RiskScore = ppa.calculatePolicyRisk(result)
	result.RiskLevel = ppa.determineRiskLevel(result.RiskScore)
	result.Recommendations = ppa.generateRecommendations(result)

	return result, nil
}

// getFineGrainedPolicies retrieves fine-grained password policies (PSOs)
func (ppa *PasswordPolicyAnalyzer) getFineGrainedPolicies() ([]*PasswordPolicyResult, error) {
	searchFilter := "(objectClass=msDS-PasswordSettings)"
	attributes := []string{
		"cn",
		"msDS-MinimumPasswordLength",
		"msDS-PasswordHistoryLength",
		"msDS-LockoutDuration",
		"msDS-LockoutObservationWindow",
		"msDS-LockoutThreshold",
		"msDS-MaximumPasswordAge",
		"msDS-MinimumPasswordAge",
		"msDS-PasswordComplexityEnabled",
	}

	entries, err := ppa.Client.SearchSubtreePaged(searchFilter, attributes, 500)
	if err != nil {
		return nil, fmt.Errorf("LDAP search failed: %v", err)
	}

	var results []*PasswordPolicyResult
	for _, entry := range entries {
		result := &PasswordPolicyResult{
			PolicyType:      "fine_grained_policy",
			Name:            entry.GetAttributeValue("cn"),
			Recommendations: []string{},
		}

		result.MinLength = parseInt(entry.GetAttributeValue("msDS-MinimumPasswordLength"))
		result.History = parseInt(entry.GetAttributeValue("msDS-PasswordHistoryLength"))
		result.LockoutDuration = parseInt(entry.GetAttributeValue("msDS-LockoutDuration"))
		result.LockoutThreshold = parseInt(entry.GetAttributeValue("msDS-LockoutThreshold"))
		result.MaxAge = parseDays(entry.GetAttributeValue("msDS-MaximumPasswordAge"))
		result.MinAge = parseDays(entry.GetAttributeValue("msDS-MinimumPasswordAge"))
		result.Complexity = entry.GetAttributeValue("msDS-PasswordComplexityEnabled") == "TRUE"

		result.RiskScore = ppa.calculatePolicyRisk(result)
		result.RiskLevel = ppa.determineRiskLevel(result.RiskScore)
		result.Recommendations = ppa.generateRecommendations(result)

		results = append(results, result)
	}

	return results, nil
}

// Helper functions

func parseInt(s string) int {
	if s == "" {
		return 0
	}
	var i int
	for _, c := range s {
		if c >= '0' && c <= '9' {
			i = i*10 + int(c-'0')
		}
	}
	return i
}

func parseDays(s string) int {
	// Windows FILETIME to days
	if s == "" {
		return 0
	}
	val := parseInt(s)
	if val == 0 {
		return 0
	}
	// FILETIME is 100-nanosecond intervals, convert to days
	return val / 864000000000
}

func (ppa *PasswordPolicyAnalyzer) calculatePolicyRisk(policy *PasswordPolicyResult) int {
	score := 0

	// Weak minimum length
	if policy.MinLength < 8 {
		score += 30
	} else if policy.MinLength < 12 {
		score += 15
	}

	// No complexity requirement
	if !policy.Complexity {
		score += 25
	}

	// No password history
	if policy.History < 3 {
		score += 20
	}

	// No lockout threshold
	if policy.LockoutThreshold == 0 || policy.LockoutThreshold > 10 {
		score += 20
	}

	// No max password age (never expires)
	if policy.MaxAge == 0 || policy.MaxAge > 90 {
		score += 15
	}

	// Cap at 100
	if score > 100 {
		score = 100
	}

	return score
}

func (ppa *PasswordPolicyAnalyzer) determineRiskLevel(score int) string {
	if score >= 70 {
		return "High"
	} else if score >= 40 {
		return "Medium"
	}
	return "Low"
}

func (ppa *PasswordPolicyAnalyzer) generateRecommendations(policy *PasswordPolicyResult) []string {
	var recs []string

	if policy.MinLength < 12 {
		recs = append(recs, "Increase minimum password length to at least 12 characters")
	}

	if !policy.Complexity {
		recs = append(recs, "Enable password complexity requirements (uppercase, lowercase, numbers, special characters)")
	}

	if policy.History < 5 {
		recs = append(recs, "Increase password history to prevent reuse (minimum 5 previous passwords)")
	}

	if policy.LockoutThreshold == 0 {
		recs = append(recs, "Configure account lockout threshold to prevent brute force attacks")
	} else if policy.LockoutThreshold > 10 {
		recs = append(recs, "Reduce lockout threshold to 5-10 attempts for better security")
	}

	if policy.MaxAge == 0 || policy.MaxAge > 90 {
		recs = append(recs, "Configure maximum password age (recommended 60-90 days)")
	}

	if len(recs) == 0 {
		recs = append(recs, "Password policy appears well-configured")
	}

	return recs
}

// GeneratePasswordPolicyReport generates a comprehensive password policy report
func (ppa *PasswordPolicyAnalyzer) GeneratePasswordPolicyReport(results []*PasswordPolicyResult) map[string]interface{} {
	report := make(map[string]interface{})

	report["total_policies"] = len(results)

	highRisk := []*PasswordPolicyResult{}
	mediumRisk := []*PasswordPolicyResult{}

	for _, result := range results {
		if result.RiskLevel == "High" {
			highRisk = append(highRisk, result)
		} else if result.RiskLevel == "Medium" {
			mediumRisk = append(mediumRisk, result)
		}
	}

	report["high_risk_count"] = len(highRisk)
	report["medium_risk_count"] = len(mediumRisk)
	report["high_risk_policies"] = highRisk
	report["medium_risk_policies"] = mediumRisk

	return report
}
