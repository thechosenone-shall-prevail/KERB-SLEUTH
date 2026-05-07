package advanced

import (
	"log"
	"strings"

	"github.com/go-ldap/ldap/v3"
	"github.com/thechosenone-shall-prevail/cold-relay/pkg/krb"
)

// LDAPConfigResult represents LDAP configuration analysis results
type LDAPConfigResult struct {
	CheckType       string   `json:"check_type"`
	Status          string   `json:"status"`
	RiskLevel       string   `json:"risk_level"`
	Findings        []string `json:"findings"`
	Recommendations []string `json:"recommendations"`
}

// LDAPConfigAnalyzer handles LDAP configuration analysis
type LDAPConfigAnalyzer struct {
	Client    *krb.LDAPClient
	AuditMode bool
}

// NewLDAPConfigAnalyzer creates a new LDAP configuration analyzer
func NewLDAPConfigAnalyzer(client *krb.LDAPClient, auditMode bool) *LDAPConfigAnalyzer {
	return &LDAPConfigAnalyzer{
		Client:    client,
		AuditMode: auditMode,
	}
}

// EnumerateLDAPMisconfigurations checks for LDAP misconfigurations
func (lca *LDAPConfigAnalyzer) EnumerateLDAPMisconfigurations() ([]*LDAPConfigResult, error) {
	log.Printf("[*] Starting LDAP configuration analysis...")

	// Check if client is available
	if lca.Client == nil || lca.Client.GetConnection() == nil {
		log.Printf("[!] LDAP client not available, returning empty results")
		return []*LDAPConfigResult{}, nil
	}

	var results []*LDAPConfigResult

	// Check for anonymous binds
	anonBind, err := lca.checkAnonymousBinds()
	if err != nil {
		log.Printf("[!] Failed to check anonymous binds: %v", err)
	} else {
		results = append(results, anonBind)
	}

	// Check for LDAP signing requirements
	signing, err := lca.checkLDAPSigning()
	if err != nil {
		log.Printf("[!] Failed to check LDAP signing: %v", err)
	} else {
		results = append(results, signing)
	}

	// Check for StartTLS support
	startTLS, err := lca.checkStartTLS()
	if err != nil {
		log.Printf("[!] Failed to check StartTLS: %v", err)
	} else {
		results = append(results, startTLS)
	}

	log.Printf("[+] Completed LDAP configuration analysis: %d checks performed", len(results))

	return results, nil
}

// checkAnonymousBinds checks if anonymous binds are allowed
func (lca *LDAPConfigAnalyzer) checkAnonymousBinds() (*LDAPConfigResult, error) {
	result := &LDAPConfigResult{
		CheckType:       "anonymous_bind",
		Findings:        []string{},
		Recommendations: []string{},
	}

	// Skip actual bind test in audit mode
	if lca.AuditMode {
		result.Status = "skipped"
		result.RiskLevel = "Low"
		result.Findings = append(result.Findings, "Anonymous bind check skipped in audit mode")
		result.Recommendations = append(result.Recommendations, "Manually verify anonymous bind settings")
		return result, nil
	}

	// Try to bind with empty credentials - this requires knowing the target address
	// For now, we'll check the LDAP configuration instead
	result.Status = "unknown"
	result.RiskLevel = "Medium"
	result.Findings = append(result.Findings, "Anonymous bind check requires manual verification")
	result.Recommendations = append(result.Recommendations, "Test anonymous binds using ldapsearch or similar tools")
	result.Recommendations = append(result.Recommendations, "Check domain security policy for anonymous bind restrictions")

	return result, nil
}

// checkLDAPSigning checks if LDAP signing is required
func (lca *LDAPConfigAnalyzer) checkLDAPSigning() (*LDAPConfigResult, error) {
	result := &LDAPConfigResult{
		CheckType:       "ldap_signing",
		Findings:        []string{},
		Recommendations: []string{},
	}

	// Check domain controller LDAP signing policy
	searchRequest := ldap.NewSearchRequest(
		lca.Client.GetBaseDN(),
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0, 0, false,
		"(objectClass=domain)",
		[]string{"ldapSigningIntegrity"},
		nil,
	)

	sr, err := lca.Client.GetConnection().Search(searchRequest)
	if err != nil {
		result.Status = "unknown"
		result.RiskLevel = "Medium"
		result.Findings = append(result.Findings, "Unable to determine LDAP signing policy")
		result.Recommendations = append(result.Recommendations, "Manually verify LDAP signing requirements")
		return result, nil
	}

	if len(sr.Entries) == 0 {
		result.Status = "unknown"
		result.RiskLevel = "Medium"
		result.Findings = append(result.Findings, "Domain object not found")
		return result, nil
	}

	signingIntegrity := sr.Entries[0].GetAttributeValue("ldapSigningIntegrity")
	if signingIntegrity == "1" {
		result.Status = "secure"
		result.RiskLevel = "Low"
		result.Findings = append(result.Findings, "LDAP signing is required")
		result.Recommendations = append(result.Recommendations, "Continue enforcing LDAP signing")
	} else {
		result.Status = "vulnerable"
		result.RiskLevel = "High"
		result.Findings = append(result.Findings, "LDAP signing not required - susceptible to relay attacks")
		result.Recommendations = append(result.Recommendations, "Enable LDAP signing requirement on all domain controllers")
		result.Recommendations = append(result.Recommendations, "Implement LDAP channel binding")
	}

	return result, nil
}

// checkStartTLS checks if StartTLS is available and supported
func (lca *LDAPConfigAnalyzer) checkStartTLS() (*LDAPConfigResult, error) {
	result := &LDAPConfigResult{
		CheckType:       "starttls",
		Findings:        []string{},
		Recommendations: []string{},
	}

	// Check if the server supports StartTLS by examining rootDSE
	searchRequest := ldap.NewSearchRequest(
		"",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0, 0, false,
		"(objectClass=*)",
		[]string{"supportedExtension"},
		nil,
	)

	sr, err := lca.Client.GetConnection().Search(searchRequest)
	if err != nil {
		result.Status = "unknown"
		result.RiskLevel = "Medium"
		result.Findings = append(result.Findings, "Unable to determine StartTLS support")
		return result, nil
	}

	if len(sr.Entries) == 0 {
		result.Status = "unknown"
		result.RiskLevel = "Medium"
		result.Findings = append(result.Findings, "RootDSE not available")
		return result, nil
	}

	supportedExtensions := sr.Entries[0].GetAttributeValues("supportedExtension")
	startTLSSupported := false
	for _, ext := range supportedExtensions {
		if strings.Contains(ext, "1.3.6.1.4.1.1466.20037") { // StartTLS OID
			startTLSSupported = true
			break
		}
	}

	if startTLSSupported {
		result.Status = "available"
		result.RiskLevel = "Low"
		result.Findings = append(result.Findings, "StartTLS is supported")
		result.Recommendations = append(result.Recommendations, "Prefer LDAPS or StartTLS over plain LDAP")
		result.Recommendations = append(result.Recommendations, "Enforce TLS for all LDAP connections")
	} else {
		result.Status = "unavailable"
		result.RiskLevel = "Medium"
		result.Findings = append(result.Findings, "StartTLS not supported")
		result.Recommendations = append(result.Recommendations, "Use LDAPS (port 636) for encrypted connections")
		result.Recommendations = append(result.Recommendations, "Consider upgrading to support StartTLS if possible")
	}

	return result, nil
}

// GenerateLDAPConfigReport generates a comprehensive LDAP configuration report
func (lca *LDAPConfigAnalyzer) GenerateLDAPConfigReport(results []*LDAPConfigResult) map[string]interface{} {
	report := make(map[string]interface{})

	report["total_checks"] = len(results)

	vulnerable := []*LDAPConfigResult{}
	secure := []*LDAPConfigResult{}
	unknown := []*LDAPConfigResult{}

	for _, result := range results {
		if result.Status == "vulnerable" {
			vulnerable = append(vulnerable, result)
		} else if result.Status == "secure" {
			secure = append(secure, result)
		} else {
			unknown = append(unknown, result)
		}
	}

	report["vulnerable_count"] = len(vulnerable)
	report["secure_count"] = len(secure)
	report["unknown_count"] = len(unknown)
	report["vulnerable_checks"] = vulnerable
	report["secure_checks"] = secure
	report["unknown_checks"] = unknown

	return report
}
