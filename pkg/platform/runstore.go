package platform

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/thechosenone-shall-prevail/cold-relay/pkg/output"
)

type RunMetadata struct {
	ID        string                 `json:"id"`
	CreatedAt string                 `json:"created_at"`
	Target    string                 `json:"target"`
	Domain    string                 `json:"domain,omitempty"`
	Mode      string                 `json:"mode"`
	Summary   output.Summary         `json:"summary"`
	Tags      map[string]interface{} `json:"tags,omitempty"`
}

type RunStore interface {
	Save(meta RunMetadata) error
}

type FileRunStore struct {
	baseDir string
}

func NewFileRunStore(baseDir string) *FileRunStore {
	return &FileRunStore{baseDir: baseDir}
}

func FromResults(results output.Results, target, mode string) RunMetadata {
	now := time.Now().UTC()
	return RunMetadata{
		ID:        now.Format("20060102T150405Z"),
		CreatedAt: now.Format(time.RFC3339),
		Target:    target,
		Domain:    results.Domain.Name,
		Mode:      mode,
		Summary:   results.Summary,
		Tags: map[string]interface{}{
			"schema_version": results.SchemaVersion,
			"candidate_count": len(results.Candidates),
		},
	}
}

func (s *FileRunStore) Save(meta RunMetadata) error {
	if s == nil || s.baseDir == "" {
		return fmt.Errorf("run store directory is empty")
	}
	if meta.ID == "" {
		return fmt.Errorf("run metadata ID is required")
	}

	if err := os.MkdirAll(s.baseDir, 0755); err != nil {
		return fmt.Errorf("create run store dir: %w", err)
	}

	filename := filepath.Join(s.baseDir, meta.ID+".json")
	data, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal run metadata: %w", err)
	}

	if err := os.WriteFile(filename, data, 0644); err != nil {
		return fmt.Errorf("write run metadata: %w", err)
	}
	return nil
}
