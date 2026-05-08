package output

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/thechosenone-shall-prevail/cold-relay/pkg/reasoning"
)

func TestWriteBloodHoundJSONEmptyPath(t *testing.T) {
	err := WriteBloodHoundJSON("", Results{})
	if err == nil {
		t.Fatal("expected error for empty path")
	}
}

func TestWriteBloodHoundJSONRelativePath(t *testing.T) {
	tmp := t.TempDir()
	oldWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	defer func() { _ = os.Chdir(oldWD) }()
	if err := os.Chdir(tmp); err != nil {
		t.Fatalf("chdir: %v", err)
	}

	out := "bloodhound.json"
	results := Results{
		AttackGraph: &reasoning.Graph{
			Nodes: []reasoning.Node{{ID: "principal:user", Type: "principal", Name: "user"}},
		},
	}
	if err := WriteBloodHoundJSON(out, results); err != nil {
		t.Fatalf("WriteBloodHoundJSON failed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(tmp, out)); err != nil {
		t.Fatalf("expected output file: %v", err)
	}
}
