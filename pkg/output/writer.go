package output

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/yourusername/kerb-sleuth/pkg/krb"
	"gopkg.in/yaml.v3"
)

type Results struct {
	Summary    Summary         `json:"summary"`
	Candidates []krb.Candidate `json:"candidates"`
}

type Summary struct {
	TotalUsers           int `json:"total_users"`
	ASREPCandidates      int `json:"asrep_candidates"`
	KerberoastCandidates int `json:"kerberoast_candidates"`
}

func WriteJSON(path string, results Results) error {
	// Ensure directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	data, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0644)
}

func WriteCSV(path string, results Results) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Write header
	header := []string{"SamAccountName", "Type", "Score", "Severity", "Reasons", "SPNs", "ExportHashPath"}
	if err := writer.Write(header); err != nil {
		return err
	}

	// Write candidates
	for _, candidate := range results.Candidates {
		severity := extractSeverity(candidate.Reasons)
		reasons := strings.Join(candidate.Reasons, "; ")
		spns := strings.Join(candidate.SPNs, "; ")

		record := []string{
			candidate.SamAccountName,
			candidate.Type,
			fmt.Sprintf("%d", candidate.Score),
			severity,
			reasons,
			spns,
			candidate.ExportHashPath,
		}

		if err := writer.Write(record); err != nil {
			return err
		}
	}

	return nil
}

func WriteHashExport(path string, results Results) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	// Write warning header
	fmt.Fprintln(file, "# KERBEROS HASH EXPORT")
	fmt.Fprintln(file, "# WARNING: These hashes are for authorized security testing only.")
	fmt.Fprintln(file, "# Ensure you have proper authorization before attempting to crack these hashes.")
	fmt.Fprintln(file, "#")
	fmt.Fprintln(file, "# Format: $krb5asrep$23$user@domain:hash (for AS-REP)")
	fmt.Fprintln(file, "# Format: $krb5tgs$23$*user$domain$service*$hash (for Kerberoast)")
	fmt.Fprintln(file, "")

	// Export AS-REP hashes
	for _, candidate := range results.Candidates {
		if candidate.Type == "ASREP" {
			// Placeholder hash format for AS-REP
			fmt.Fprintf(file, "$krb5asrep$23$%s@DOMAIN.LOCAL:HASH_PLACEHOLDER_%s\n",
				candidate.SamAccountName, candidate.SamAccountName)
		} else if candidate.Type == "KERBEROAST" {
			// Placeholder hash format for Kerberoast
			for _, spn := range candidate.SPNs {
				fmt.Fprintf(file, "$krb5tgs$23$*%s$DOMAIN.LOCAL$%s*$HASH_PLACEHOLDER_%s\n",
					candidate.SamAccountName, spn, candidate.SamAccountName)
			}
		}
	}

	// Write README
	readmePath := filepath.Join(dir, "README.txt")
	readme := `KERBEROS HASH CRACKING GUIDE
=============================

WARNING: Ensure you have proper authorization before cracking these hashes.

CRACKING WITH HASHCAT:
----------------------
AS-REP hashes (mode 18200):
  hashcat -m 18200 -a 0 kerb_hashes.txt rockyou.txt

Kerberoast hashes (mode 13100):
  hashcat -m 13100 -a 0 kerb_hashes.txt rockyou.txt

CRACKING WITH JOHN THE RIPPER:
-------------------------------
  john --wordlist=rockyou.txt kerb_hashes.txt
  john --show kerb_hashes.txt

LEGAL NOTICE:
-------------
These hashes are exported for authorized security testing only.
Unauthorized access to computer systems is illegal and punishable by law.
`

	return os.WriteFile(readmePath, []byte(readme), 0644)
}

func WriteSigmaRules(path string, results Results) error {
	rules := []map[string]interface{}{
		{
			"title":       "AS-REP Roasting Detection",
			"description": "Detects potential AS-REP roasting attempts",
			"status":      "experimental",
			"logsource": map[string]string{
				"product": "windows",
				"service": "security",
			},
			"detection": map[string]interface{}{
				"selection": map[string]interface{}{
					"EventID":     4768,
					"PreAuthType": 0,
				},
				"condition": "selection",
			},
			"level": "high",
		},
		{
			"title":       "Kerberoasting Detection",
			"description": "Detects potential Kerberoasting attempts",
			"status":      "experimental",
			"logsource": map[string]string{
				"product": "windows",
				"service": "security",
			},
			"detection": map[string]interface{}{
				"selection": map[string]interface{}{
					"EventID":       4769,
					"ServiceName":   "*$",
					"TicketOptions": "0x40810000",
				},
				"condition": "selection",
			},
			"level": "high",
		},
	}

	data, err := yaml.Marshal(rules)
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0644)
}

func extractSeverity(reasons []string) string {
	for _, reason := range reasons {
		if strings.Contains(reason, "Severity:") {
			parts := strings.Split(reason, ":")
			if len(parts) >= 2 {
				return strings.TrimSpace(parts[1])
			}
		}
	}
	return "Unknown"
}
