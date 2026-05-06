package krb

import "testing"

func TestSetCandidateValidationMergesUniqueDetails(t *testing.T) {
	candidate := Candidate{
		Validation:  StatusLikely,
		Evidence:    []string{"existing evidence"},
		Blockers:    []string{"existing blocker"},
		NextActions: []string{"existing action"},
	}

	SetCandidateValidation(&candidate, StatusValidated,
		[]string{"existing evidence", "new evidence"},
		[]string{"existing blocker", "new blocker"},
		[]string{"existing action", "new action"},
	)

	if candidate.Validation != StatusValidated {
		t.Fatalf("expected validation %q, got %q", StatusValidated, candidate.Validation)
	}
	if got := len(candidate.Evidence); got != 2 {
		t.Fatalf("expected 2 unique evidence items, got %d: %#v", got, candidate.Evidence)
	}
	if got := len(candidate.Blockers); got != 2 {
		t.Fatalf("expected 2 unique blockers, got %d: %#v", got, candidate.Blockers)
	}
	if got := len(candidate.NextActions); got != 2 {
		t.Fatalf("expected 2 unique next actions, got %d: %#v", got, candidate.NextActions)
	}
}
