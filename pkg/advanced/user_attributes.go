package advanced

import (
	"fmt"
	"log"
	"strconv"

	"github.com/go-ldap/ldap/v3"
	"github.com/thechosenone-shall-prevail/cold-relay/pkg/krb"
)

// UserAttributeResult represents user attribute analysis results
type UserAttributeResult struct {
	SAMAccountName       string   `json:"sam_account_name"`
	DistinguishedName    string   `json:"distinguished_name"`
	UserAccountControl   int      `json:"user_account_control"`
	PasswordNotRequired  bool     `json:"password_not_required"`
	PasswordNeverExpires bool     `json:"password_never_expires"`
	AccountDisabled      bool     `json:"account_disabled"`
	AccountLocked        bool     `json:"account_locked"`
	SIDHistory           []string `json:"sid_history,omitempty"`
	PrimaryGroupID       int      `json:"primary_group_id"`
	RiskScore            int      `json:"risk_score"`
	RiskLevel            string   `json:"risk_level"`
	Flags                []string `json:"flags"`
	Recommendations      []string `json:"recommendations"`
}

// UserAttributeAnalyzer handles user attribute analysis
type UserAttributeAnalyzer struct {
	Client    *krb.LDAPClient
	AuditMode bool
}

// NewUserAttributeAnalyzer creates a new user attribute analyzer
func NewUserAttributeAnalyzer(client *krb.LDAPClient, auditMode bool) *UserAttributeAnalyzer {
	return &UserAttributeAnalyzer{
		Client:    client,
		AuditMode: auditMode,
	}
}

// EnumerateUserAttributes enumerates and analyzes user attributes
func (uaa *UserAttributeAnalyzer) EnumerateUserAttributes() ([]*UserAttributeResult, error) {
	log.Printf("[*] Starting user attribute analysis...")

	// Check if client is available
	if uaa.Client == nil || uaa.Client.GetConnection() == nil {
		log.Printf("[!] LDAP client not available, returning empty results")
		return []*UserAttributeResult{}, nil
	}

	// Search for user objects
	searchFilter := "(&(objectCategory=person)(objectClass=user))"
	attributes := []string{
		"distinguishedName",
		"sAMAccountName",
		"userAccountControl",
		"sIDHistory",
		"primaryGroupID",
		"lockoutTime",
	}

	entries, err := uaa.Client.SearchSubtreePaged(searchFilter, attributes, 500)
	if err != nil {
		return nil, fmt.Errorf("LDAP search failed: %v", err)
	}

	log.Printf("[+] Found %d user objects for attribute analysis", len(entries))

	var results []*UserAttributeResult
	for _, entry := range entries {
		result, err := uaa.analyzeUserAttributes(entry)
		if err != nil {
			log.Printf("[x] Failed to analyze user attributes for %s: %v", entry.DN, err)
			continue
		}
		results = append(results, result)
	}

	return results, nil
}

// AnalyzeUserAttributeRisk analyzes risk for a specific user
func (uaa *UserAttributeAnalyzer) AnalyzeUserAttributeRisk(samAccountName string) (*UserAttributeResult, error) {
	log.Printf("[*] Analyzing user attribute risk for: %s", samAccountName)

	searchFilter := fmt.Sprintf("(sAMAccountName=%s)", ldap.EscapeFilter(samAccountName))
	searchRequest := ldap.NewSearchRequest(
		uaa.Client.GetBaseDN(),
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, 0, false,
		searchFilter,
		[]string{"distinguishedName", "sAMAccountName", "userAccountControl", "sIDHistory", "primaryGroupID", "lockoutTime"},
		nil,
	)

	sr, err := uaa.Client.GetConnection().Search(searchRequest)
	if err != nil {
		return nil, fmt.Errorf("LDAP search failed: %v", err)
	}

	if len(sr.Entries) == 0 {
		return nil, fmt.Errorf("user not found: %s", samAccountName)
	}

	return uaa.analyzeUserAttributes(sr.Entries[0])
}

// DetectAttributeAbuse detects potential attribute abuse patterns
func (uaa *UserAttributeAnalyzer) DetectAttributeAbuse(results []*UserAttributeResult) []string {
	var patterns []string

	for _, result := range results {
		if result.RiskScore > 70 {
			patterns = append(patterns, fmt.Sprintf("High-risk user attributes: %s (score: %d)", result.SAMAccountName, result.RiskScore))
		}

		if result.PasswordNotRequired {
			patterns = append(patterns, fmt.Sprintf("Password not required flag set: %s", result.SAMAccountName))
		}

		if result.PasswordNeverExpires {
			patterns = append(patterns, fmt.Sprintf("Password never expires flag set: %s", result.SAMAccountName))
		}

		if len(result.SIDHistory) > 0 {
			patterns = append(patterns, fmt.Sprintf("SID history present: %s (%d SIDs)", result.SAMAccountName, len(result.SIDHistory)))
		}
	}

	return patterns
}

// Helper functions

func (uaa *UserAttributeAnalyzer) analyzeUserAttributes(entry *ldap.Entry) (*UserAttributeResult, error) {
	result := &UserAttributeResult{
		SAMAccountName:    entry.GetAttributeValue("sAMAccountName"),
		DistinguishedName: entry.DN,
		Flags:             []string{},
		Recommendations:   []string{},
	}

	// Parse userAccountControl
	uacStr := entry.GetAttributeValue("userAccountControl")
	uac, err := strconv.Atoi(uacStr)
	if err == nil {
		result.UserAccountControl = uac
		result.PasswordNotRequired = (uac & 0x0020) != 0   // UF_PASSWD_NOTREQD
		result.PasswordNeverExpires = (uac & 0x10000) != 0 // UF_DONT_EXPIRE_PASSWD
		result.AccountDisabled = (uac & 0x0002) != 0       // UF_ACCOUNTDISABLE
		result.AccountLocked = (uac & 0x0010) != 0         // UF_LOCKOUT

		// Collect flags
		if result.PasswordNotRequired {
			result.Flags = append(result.Flags, "UF_PASSWD_NOTREQD")
		}
		if result.PasswordNeverExpires {
			result.Flags = append(result.Flags, "UF_DONT_EXPIRE_PASSWD")
		}
		if result.AccountDisabled {
			result.Flags = append(result.Flags, "UF_ACCOUNTDISABLE")
		}
		if result.AccountLocked {
			result.Flags = append(result.Flags, "UF_LOCKOUT")
		}
	}

	// Parse SID history
	sidHistory := entry.GetAttributeValues("sIDHistory")
	result.SIDHistory = sidHistory

	// Parse primary group ID
	pgidStr := entry.GetAttributeValue("primaryGroupID")
	pgid, err := strconv.Atoi(pgidStr)
	if err == nil {
		result.PrimaryGroupID = pgid
	}

	// Calculate risk score
	result.RiskScore = uaa.calculateRiskScore(result)

	// Determine risk level
	result.RiskLevel = uaa.determineRiskLevel(result.RiskScore)

	// Generate recommendations
	result.Recommendations = uaa.generateRecommendations(result)

	return result, nil
}

func (uaa *UserAttributeAnalyzer) calculateRiskScore(result *UserAttributeResult) int {
	score := 0

	// Password not required is high risk
	if result.PasswordNotRequired {
		score += 40
	}

	// Password never expires increases risk
	if result.PasswordNeverExpires {
		score += 25
	}

	// SID history can be abused for persistence
	if len(result.SIDHistory) > 0 {
		score += 20
	}

	// Unusual primary group ID
	if result.PrimaryGroupID != 513 { // Default is Domain Users (513)
		score += 15
	}

	// Account locked is concerning
	if result.AccountLocked {
		score += 10
	}

	// Cap at 100
	if score > 100 {
		score = 100
	}

	return score
}

func (uaa *UserAttributeAnalyzer) determineRiskLevel(score int) string {
	if score >= 70 {
		return "High"
	} else if score >= 40 {
		return "Medium"
	}
	return "Low"
}

func (uaa *UserAttributeAnalyzer) generateRecommendations(result *UserAttributeResult) []string {
	var recs []string

	if result.PasswordNotRequired {
		recs = append(recs, "Remove UF_PASSWD_NOTREQD flag - accounts should require passwords")
	}

	if result.PasswordNeverExpires {
		recs = append(recs, "Review UF_DONT_EXPIRE_PASSWD flag - implement password expiration policies")
	}

	if len(result.SIDHistory) > 0 {
		recs = append(recs, "Review SID history entries for potential abuse or stale SIDs")
	}

	if result.PrimaryGroupID != 513 {
		recs = append(recs, fmt.Sprintf("Review primary group ID %d - ensure it's legitimate", result.PrimaryGroupID))
	}

	if result.AccountLocked {
		recs = append(recs, "Investigate account lockout - may indicate brute force attempts")
	}

	if len(recs) == 0 {
		recs = append(recs, "User attributes appear normal - continue monitoring")
	}

	return recs
}

// GenerateUserAttributeReport generates a comprehensive user attribute report
func (uaa *UserAttributeAnalyzer) GenerateUserAttributeReport(results []*UserAttributeResult) map[string]interface{} {
	report := make(map[string]interface{})

	report["total_users_analyzed"] = len(results)

	passwordNotRequired := []*UserAttributeResult{}
	passwordNeverExpires := []*UserAttributeResult{}
	sidHistoryPresent := []*UserAttributeResult{}
	highRisk := []*UserAttributeResult{}

	for _, result := range results {
		if result.PasswordNotRequired {
			passwordNotRequired = append(passwordNotRequired, result)
		}
		if result.PasswordNeverExpires {
			passwordNeverExpires = append(passwordNeverExpires, result)
		}
		if len(result.SIDHistory) > 0 {
			sidHistoryPresent = append(sidHistoryPresent, result)
		}
		if result.RiskLevel == "High" {
			highRisk = append(highRisk, result)
		}
	}

	report["password_not_required_count"] = len(passwordNotRequired)
	report["password_never_expires_count"] = len(passwordNeverExpires)
	report["sid_history_count"] = len(sidHistoryPresent)
	report["high_risk_count"] = len(highRisk)
	report["password_not_required_users"] = passwordNotRequired
	report["password_never_expires_users"] = passwordNeverExpires
	report["sid_history_users"] = sidHistoryPresent
	report["high_risk_users"] = highRisk

	// Abuse patterns
	patterns := uaa.DetectAttributeAbuse(results)
	report["abuse_patterns"] = patterns

	return report
}
