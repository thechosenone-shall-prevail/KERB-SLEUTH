package advanced

import (
	"errors"
	"strings"
	"testing"
)

func TestExplainSMBError(t *testing.T) {
	cases := []struct {
		name     string
		err      error
		expected string
	}{
		{
			name:     "access denied",
			err:      errors.New("STATUS_ACCESS_DENIED"),
			expected: "access denied",
		},
		{
			name:     "auth failure",
			err:      errors.New("STATUS_LOGON_FAILURE"),
			expected: "authentication failed",
		},
		{
			name:     "network timeout",
			err:      errors.New("dial tcp 10.0.0.1:445: i/o timeout"),
			expected: "network timeout",
		},
		{
			name:     "share missing",
			err:      errors.New("STATUS_BAD_NETWORK_NAME"),
			expected: "share does not exist",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ExplainSMBError(tc.err)
			if got == "" || !strings.Contains(got, tc.expected) {
				t.Fatalf("expected %q to contain %q", got, tc.expected)
			}
		})
	}
}
