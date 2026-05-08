package platform

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFileRunStoreSave(t *testing.T) {
	tmp := t.TempDir()
	store := NewFileRunStore(tmp)

	meta := RunMetadata{
		ID:        "20260508T073000Z",
		CreatedAt: "2026-05-08T07:30:00Z",
		Target:    "dc01.example.local",
		Mode:      "passive",
	}

	if err := store.Save(meta); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	path := filepath.Join(tmp, meta.ID+".json")
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected saved metadata file: %v", err)
	}
}

func TestFileRunStoreSaveMissingID(t *testing.T) {
	store := NewFileRunStore(t.TempDir())
	if err := store.Save(RunMetadata{}); err == nil {
		t.Fatal("expected error for missing ID")
	}
}
