package krb

const (
	StatusValidated              = "validated"
	StatusLikely                 = "likely"
	StatusTheoretical            = "theoretical"
	StatusBlocked                = "blocked"
	StatusInsufficientVisibility = "insufficient_visibility"
)

func SetCandidateValidation(c *Candidate, status string, evidence, blockers, nextActions []string) {
	if c == nil {
		return
	}
	c.Validation = status
	c.Evidence = appendUnique(c.Evidence, evidence...)
	c.Blockers = appendUnique(c.Blockers, blockers...)
	c.NextActions = appendUnique(c.NextActions, nextActions...)
}

func appendUnique(existing []string, values ...string) []string {
	seen := make(map[string]bool, len(existing)+len(values))
	out := make([]string, 0, len(existing)+len(values))
	for _, value := range existing {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	for _, value := range values {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}
