package controlplane

type Status string

const (
	StatusProvenTrue  Status = "proven_true"
	StatusProvenFalse Status = "proven_false"
	StatusUnknown     Status = "unknown"
	StatusError       Status = "error"
)

type Graph struct {
	Nodes    []Node        `json:"nodes,omitempty"`
	Edges    []Edge        `json:"edges,omitempty"`
	Coverage []CoverageGap `json:"coverage,omitempty"`
}

type Node struct {
	ID   string `json:"id"`
	Type string `json:"type"`
	Name string `json:"name"`
}

type Edge struct {
	Source       string   `json:"source"`
	Target       string   `json:"target"`
	Right        string   `json:"right"`
	Status       Status   `json:"status"`
	Evidence     []string `json:"evidence,omitempty"`
	Conditions   []string `json:"conditions,omitempty"`
	HowToVerify  []string `json:"how_to_verify,omitempty"`
	SourceModule string   `json:"source_module,omitempty"`
}

type CoverageGap struct {
	Area      string `json:"area"`
	Status    Status `json:"status"`
	Gap       string `json:"gap"`
	Detail    string `json:"detail,omitempty"`
	NextCheck string `json:"next_check,omitempty"`
}

