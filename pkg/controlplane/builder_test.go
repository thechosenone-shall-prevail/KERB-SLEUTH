package controlplane

import (
	"testing"

	"github.com/thechosenone-shall-prevail/cold-relay/pkg/reasoning"
)

func TestBuildFromReasoningAddsEdgesAndCoverage(t *testing.T) {
	g := &reasoning.Graph{
		Nodes: []reasoning.Node{
			{ID: "principal:alice", Type: "principal", Name: "alice"},
			{ID: "group:da", Type: "group", Name: "Domain Admins"},
		},
		Edges: []reasoning.Edge{
			{From: "principal:alice", To: "group:da", Type: "member_of", Validation: "validated", Evidence: []string{"LDAP memberOf"}},
		},
	}
	cp := BuildFromReasoning(g, map[string]interface{}{})
	if len(cp.Edges) == 0 {
		t.Fatal("expected mapped control edges")
	}
	if cp.Edges[0].Right != "MemberOf" {
		t.Fatalf("expected MemberOf right, got %q", cp.Edges[0].Right)
	}
	if len(cp.Coverage) == 0 {
		t.Fatal("expected coverage gaps")
	}
}

