package krb

import (
	"strings"
	"time"

	"github.com/thechosenone-shall-prevail/kerb-sleuth/pkg/ingest"
)

type Candidate struct {
	SamAccountName string
	Type           string // "ASREP" | "KERBEROAST"
	Score          int
	Reasons        []string
	SPNs           []string
	PwdLastSet     time.Time
	MemberOf       []string
	ExportHashPath string
	Hash           string // Actual extracted hash
	Domain         string // Domain name
}

func FindASREPCandidates(users []ingest.User) []Candidate {
	var candidates []Candidate

	for _, user := range users {
		// Skip machine accounts unless specifically included
		if strings.HasSuffix(user.SamAccountName, "$") {
			continue
		}

		// Skip disabled accounts (UAC flag 0x2)
		if user.UserAccountControl&0x2 != 0 {
			continue
		}

		// Check for DoesNotRequirePreAuth
		if user.DoesNotRequirePreAuth || (user.UserAccountControl&0x400000) != 0 {
			candidate := Candidate{
				SamAccountName: user.SamAccountName,
				Type:           "ASREP",
				PwdLastSet:     user.PwdLastSet,
				MemberOf:       user.MemberOf,
				Reasons:        []string{"DoesNotRequirePreAuth flag set"},
			}

			// Add additional context
			if user.UserAccountControl&0x400000 != 0 {
				candidate.Reasons = append(candidate.Reasons, "UAC DONT_REQ_PREAUTH (0x400000)")
			}

			if time.Since(user.PwdLastSet).Hours() > 90*24 {
				candidate.Reasons = append(candidate.Reasons, "Password older than 90 days")
			}

			if hasAdminGroup(user.MemberOf) {
				candidate.Reasons = append(candidate.Reasons, "Member of privileged group")
			}

			candidates = append(candidates, candidate)
		}
	}

	return candidates
}

func FindKerberoastCandidates(users []ingest.User) []Candidate {
	var candidates []Candidate

	for _, user := range users {
		// Skip machine accounts by default
		if strings.HasSuffix(user.SamAccountName, "$") {
			continue
		}

		// Skip disabled accounts
		if user.UserAccountControl&0x2 != 0 {
			continue
		}

		// Check for SPNs
		if len(user.ServicePrincipalNames) > 0 {
			candidate := Candidate{
				SamAccountName: user.SamAccountName,
				Type:           "KERBEROAST",
				PwdLastSet:     user.PwdLastSet,
				MemberOf:       user.MemberOf,
				SPNs:           user.ServicePrincipalNames,
				Reasons:        []string{"Has Service Principal Names"},
			}

			// Add SPN details to reasons
			for _, spn := range user.ServicePrincipalNames {
				candidate.Reasons = append(candidate.Reasons, "SPN: "+spn)
			}

			if time.Since(user.PwdLastSet).Hours() > 90*24 {
				candidate.Reasons = append(candidate.Reasons, "Password older than 90 days")
			}

			if hasAdminGroup(user.MemberOf) {
				candidate.Reasons = append(candidate.Reasons, "Member of privileged group")
			}

			candidates = append(candidates, candidate)
		}
	}

	return candidates
}

func hasAdminGroup(groups []string) bool {
	adminGroups := []string{
		"Domain Admins",
		"Enterprise Admins",
		"Schema Admins",
		"Administrators",
		"Account Operators",
		"Backup Operators",
		"Server Operators",
	}

	for _, group := range groups {
		groupLower := strings.ToLower(group)
		for _, admin := range adminGroups {
			if strings.Contains(groupLower, strings.ToLower(admin)) {
				return true
			}
		}
	}

	return false
}
