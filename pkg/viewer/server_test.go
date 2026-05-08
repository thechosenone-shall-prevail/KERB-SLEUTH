package viewer

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/thechosenone-shall-prevail/cold-relay/pkg/output"
	"github.com/thechosenone-shall-prevail/cold-relay/pkg/reasoning"
)

func TestLoadPayload(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "results.json")

	results := output.Results{
		SchemaVersion: "2.0",
		Domain: output.DomainInfo{
			Name: "EXAMPLE.LOCAL",
		},
		AttackGraph: &reasoning.Graph{
			Nodes: []reasoning.Node{
				{ID: "principal:alice", Type: "principal", Name: "alice"},
				{ID: "group:domain_admins", Type: "group", Name: "Domain Admins"},
			},
			Edges: []reasoning.Edge{
				{From: "principal:alice", To: "group:domain_admins", Type: "member_of", Validation: "validated"},
			},
		},
	}

	data, err := json.Marshal(results)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	payload, err := loadPayload(path)
	if err != nil {
		t.Fatalf("loadPayload failed: %v", err)
	}
	if len(payload.Nodes) != 2 {
		t.Fatalf("expected 2 nodes, got %d", len(payload.Nodes))
	}
	if len(payload.Links) != 1 {
		t.Fatalf("expected 1 link, got %d", len(payload.Links))
	}
}
