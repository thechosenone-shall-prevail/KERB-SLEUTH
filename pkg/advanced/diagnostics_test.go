package advanced

import (
	"errors"
	"strings"
	"testing"
)

func TestExplainProtocolError(t *testing.T) {
	tests := []struct {
		module   string
		err      error
		contains string
	}{
		{"smb", errors.New("STATUS_ACCESS_DENIED"), "access denied"},
		{"dns", errors.New("transfer refused"), "refused"},
		{"rbcd", errors.New("LDAP Result Code 49"), "authentication failed"},
		{"gpo", errors.New("insufficientAccessRights"), "lacks directory read rights"},
	}

	for _, tt := range tests {
		got := ExplainProtocolError(tt.module, tt.err)
		if !strings.Contains(strings.ToLower(got), strings.ToLower(tt.contains)) {
			t.Fatalf("module=%s got=%q missing=%q", tt.module, got, tt.contains)
		}
	}
}
