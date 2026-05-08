package output

import (
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/thechosenone-shall-prevail/cold-relay/pkg/krb"
	"github.com/thechosenone-shall-prevail/cold-relay/pkg/reasoning"
)

// ReportData holds the data for the HTML report template
type ReportData struct {
	GeneratedAt          string
	SchemaVersion        string
	Domain               DomainInfo
	Summary              Summary
	Candidates           []CandidateReport
	ConfirmedCandidates  []CandidateReport
	ReviewCandidates     []CandidateReport
	AttackPaths          []AttackPathReport
	RiskInsights         []string
	HeuristicAdvisories  []string
	ValidationCounts     map[string]int
	MermaidDiagrams      []string
	OverallRiskScore     int
	RiskLevel            string
	SeverityDistribution map[string]int
	TypeDistribution     map[string]int
	ExecutiveSummary     ExecutiveSummary
	FullJSONOutput       string
}

// ExecutiveSummary provides high-level overview for management
type ExecutiveSummary struct {
	CriticalFindings int
	HighFindings     int
	MediumFindings   int
	LowFindings      int
	TopRisks         []string
	QuickWins        []string
	EstimatedEffort  string
	ComplianceImpact string
}

// CandidateReport formats a candidate for the report
type CandidateReport struct {
	SamAccountName     string
	Type               string
	Score              int
	Validation         string
	Severity           string
	Reasons            []string
	Evidence           []string
	Blockers           []string
	NextActions        []string
	SPNs               []string
	RemediationSteps   []string
	PowerShellCommands []string
	DetectionGuidance  []string
}

// AttackPathReport formats an attack path for the report
type AttackPathReport struct {
	Title      string
	Severity   string
	Validation string
	Steps      []string
	Evidence   []string
	Blockers   []string
}

// WriteHTMLReport generates a professional HTML report
func WriteHTMLReport(path string, results Results) error {
	// Ensure directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	// Prepare report data
	data := prepareReportData(results)

	// Create template with custom functions
	funcMap := template.FuncMap{
		"toLower": strings.ToLower,
	}
	tmpl, err := template.New("report").Funcs(funcMap).Parse(htmlTemplate)
	if err != nil {
		return fmt.Errorf("failed to parse template: %v", err)
	}

	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	if err := tmpl.Execute(file, data); err != nil {
		return fmt.Errorf("failed to execute template: %v", err)
	}

	return nil
}

// prepareReportData converts Results to ReportData
func prepareReportData(results Results) ReportData {
	data := ReportData{
		GeneratedAt:          time.Now().Format("2006-01-02 15:04:05 MST"),
		SchemaVersion:        results.SchemaVersion,
		Domain:               results.Domain,
		Summary:              results.Summary,
		RiskInsights:         results.RiskInsights,
		ValidationCounts:     make(map[string]int),
		MermaidDiagrams:      make([]string, 0),
		SeverityDistribution: make(map[string]int),
		TypeDistribution:     make(map[string]int),
	}

	// Calculate overall risk score
	data.OverallRiskScore = calculateOverallRiskScore(results)
	data.RiskLevel = getRiskLevel(data.OverallRiskScore)

	// Marshal full JSON output
	jsonBytes, _ := json.MarshalIndent(results, "", "  ")
	data.FullJSONOutput = string(jsonBytes)

	// Convert candidates with enhanced remediation
	for _, c := range results.Candidates {
		candidate := CandidateReport{
			SamAccountName:     c.SamAccountName,
			Type:               c.Type,
			Score:              c.Score,
			Validation:         c.Validation,
			Severity:           extractSeverity(c.Reasons),
			Reasons:            c.Reasons,
			Evidence:           c.Evidence,
			Blockers:           c.Blockers,
			NextActions:        c.NextActions,
			SPNs:               c.SPNs,
			RemediationSteps:   generateRemediationSteps(c),
			PowerShellCommands: generatePowerShellCommands(c),
			DetectionGuidance:  generateDetectionGuidance(c),
		}
		data.Candidates = append(data.Candidates, candidate)

		// Track severity distribution
		data.SeverityDistribution[candidate.Severity]++

		// Track type distribution
		data.TypeDistribution[c.Type]++

		if c.Validation == "validated" {
			data.ConfirmedCandidates = append(data.ConfirmedCandidates, candidate)
		} else {
			data.ReviewCandidates = append(data.ReviewCandidates, candidate)
		}
		if c.Validation == "likely" || c.Validation == "theoretical" {
			data.HeuristicAdvisories = append(data.HeuristicAdvisories,
				fmt.Sprintf("%s (%s): heuristic-confidence finding, double-verify before operational decisions.", c.SamAccountName, c.Type))
		}

		// Count validation statuses
		if c.Validation != "" {
			data.ValidationCounts[c.Validation]++
		}
	}

	// Generate executive summary
	data.ExecutiveSummary = generateExecutiveSummary(results, data)

	// Convert attack paths from graph and generate Mermaid diagrams
	if results.AttackGraph != nil {
		for _, path := range results.AttackGraph.AttackPaths {
			steps := make([]string, 0, len(path.Steps))
			for _, step := range path.Steps {
				steps = append(steps, fmt.Sprintf("%s → %s: %s", step.From, step.To, step.Action))
			}

			attackPath := AttackPathReport{
				Title:      path.Title,
				Severity:   path.Severity,
				Validation: path.Validation,
				Steps:      steps,
				Evidence:   path.Evidence,
				Blockers:   path.Blockers,
			}
			data.AttackPaths = append(data.AttackPaths, attackPath)

			// Generate Mermaid diagram for this path
			if len(path.Steps) > 0 {
				mermaid := generateMermaidDiagram(path)
				data.MermaidDiagrams = append(data.MermaidDiagrams, mermaid)
			}
		}
	}

	return data
}

// calculateOverallRiskScore computes an aggregate risk score (0-100)
func calculateOverallRiskScore(results Results) int {
	score := 0
	weights := map[string]int{
		"validated":               10,
		"likely":                  7,
		"theoretical":             4,
		"blocked":                 2,
		"insufficient_visibility": 1,
	}

	// Score based on validation status
	for status, count := range results.Summary.ValidationStatus {
		if weight, ok := weights[status]; ok {
			score += count * weight
		}
	}

	// Bonus for critical findings
	score += results.Summary.ASREPCandidates * 5
	score += results.Summary.KerberoastCandidates * 5
	score += results.Summary.HVTCandidates * 3

	// Check for pwned status
	if results.Advanced.Pwned {
		score += 50
	}

	// Normalize to 0-100
	if score > 100 {
		score = 100
	}

	return score
}

// getRiskLevel returns the risk level based on score
func getRiskLevel(score int) string {
	if score >= 80 {
		return "CRITICAL"
	} else if score >= 60 {
		return "HIGH"
	} else if score >= 40 {
		return "MEDIUM"
	}
	return "LOW"
}

// generateExecutiveSummary creates executive summary for management
func generateExecutiveSummary(results Results, data ReportData) ExecutiveSummary {
	summary := ExecutiveSummary{
		TopRisks:  make([]string, 0),
		QuickWins: make([]string, 0),
	}

	// Count findings by severity
	for severity, count := range data.SeverityDistribution {
		switch strings.ToLower(severity) {
		case "critical":
			summary.CriticalFindings = count
		case "high":
			summary.HighFindings = count
		case "medium":
			summary.MediumFindings = count
		case "low":
			summary.LowFindings = count
		}
	}

	// Identify top risks
	if results.Advanced.Pwned {
		summary.TopRisks = append(summary.TopRisks, "Administrative SMB access confirmed - immediate local admin compromise possible")
	}
	if results.Summary.ASREPCandidates > 0 {
		summary.TopRisks = append(summary.TopRisks, fmt.Sprintf("%d accounts vulnerable to AS-REP roasting with offline password cracking", results.Summary.ASREPCandidates))
	}
	if results.Summary.KerberoastCandidates > 0 {
		summary.TopRisks = append(summary.TopRisks, fmt.Sprintf("%d service accounts vulnerable to Kerberoasting attacks", results.Summary.KerberoastCandidates))
	}
	if results.Summary.HVTCandidates > 0 {
		summary.TopRisks = append(summary.TopRisks, fmt.Sprintf("%d high-value privileged accounts identified as potential targets", results.Summary.HVTCandidates))
	}
	if len(results.Advanced.SensitiveFiles) > 0 {
		summary.TopRisks = append(summary.TopRisks, fmt.Sprintf("%d sensitive files accessible on network shares", len(results.Advanced.SensitiveFiles)))
	}

	// Identify quick wins
	if results.Summary.ASREPCandidates > 0 {
		summary.QuickWins = append(summary.QuickWins, "Enable Kerberos pre-authentication on all user accounts")
	}
	if len(results.Advanced.SensitiveFiles) > 0 {
		summary.QuickWins = append(summary.QuickWins, "Restrict permissions on sensitive network shares")
	}
	if results.Summary.KerberoastCandidates > 0 {
		summary.QuickWins = append(summary.QuickWins, "Rotate service account passwords with 25+ character complexity")
	}

	// Estimate remediation effort
	totalFindings := summary.CriticalFindings + summary.HighFindings + summary.MediumFindings + summary.LowFindings
	if totalFindings > 20 {
		summary.EstimatedEffort = "4-6 weeks for full remediation"
	} else if totalFindings > 10 {
		summary.EstimatedEffort = "2-4 weeks for full remediation"
	} else if totalFindings > 5 {
		summary.EstimatedEffort = "1-2 weeks for full remediation"
	} else {
		summary.EstimatedEffort = "Less than 1 week for full remediation"
	}

	// Compliance impact
	if data.OverallRiskScore >= 80 {
		summary.ComplianceImpact = "Critical compliance gaps identified. Immediate action required for SOC2, ISO 27001, PCI-DSS compliance."
	} else if data.OverallRiskScore >= 60 {
		summary.ComplianceImpact = "Significant compliance risks present. Remediation recommended before next audit cycle."
	} else if data.OverallRiskScore >= 40 {
		summary.ComplianceImpact = "Moderate compliance concerns. Address findings to maintain security posture."
	} else {
		summary.ComplianceImpact = "Compliance posture acceptable. Continue monitoring and maintain current controls."
	}

	return summary
}

// generateRemediationSteps creates actionable remediation steps
func generateRemediationSteps(c krb.Candidate) []string {
	steps := make([]string, 0)

	switch c.Type {
	case "ASREP":
		steps = append(steps, "Enable Kerberos pre-authentication for this account")
		steps = append(steps, "Rotate the account password immediately")
		steps = append(steps, "Review and minimize group memberships")
		steps = append(steps, "Enable account activity monitoring")
		steps = append(steps, "Consider implementing account usage restrictions")

	case "KERBEROAST":
		steps = append(steps, "Use a strong, randomly-generated password (25+ characters)")
		steps = append(steps, "Enable AES256 encryption for Kerberos")
		steps = append(steps, "Review if all SPNs are necessary; remove unused ones")
		steps = append(steps, "Consider using Group Managed Service Accounts (gMSA)")
		steps = append(steps, "Implement service account monitoring")

	case "HVT":
		steps = append(steps, "Enforce MFA for this privileged account")
		steps = append(steps, "Use Privileged Access Workstations (PAW)")
		steps = append(steps, "Implement Just-In-Time (JIT) access")
		steps = append(steps, "Enable advanced threat protection")
		steps = append(steps, "Review and minimize privileged group memberships")

	case "LOOT":
		steps = append(steps, "Remove plaintext credentials from LDAP attributes immediately")
		steps = append(steps, "Rotate all exposed credentials")
		steps = append(steps, "Audit all systems where credentials may have been reused")
		steps = append(steps, "Implement secret management solution (e.g., CyberArk, HashiCorp Vault)")
		steps = append(steps, "Review and restrict LDAP attribute write permissions")

	case "RECON":
		steps = append(steps, "Review and restrict share permissions")
		steps = append(steps, "Remove sensitive files from accessible shares")
		steps = append(steps, "Implement file access monitoring")
		steps = append(steps, "Use encryption for sensitive data at rest")
		steps = append(steps, "Regular audit of share permissions")

	default:
		steps = append(steps, "Review finding details and assess risk")
		steps = append(steps, "Implement appropriate security controls")
		steps = append(steps, "Monitor for exploitation attempts")
	}

	return steps
}

// generatePowerShellCommands creates PowerShell remediation commands
func generatePowerShellCommands(c krb.Candidate) []string {
	commands := make([]string, 0)

	switch c.Type {
	case "ASREP":
		commands = append(commands, fmt.Sprintf("# Enable Kerberos pre-authentication\nSet-ADUser -Identity '%s' -KerberosEncryptionType AES256", c.SamAccountName))
		commands = append(commands, fmt.Sprintf("# Force password change\nSet-ADUser -Identity '%s' -ChangePasswordAtLogon $true", c.SamAccountName))
		commands = append(commands, fmt.Sprintf("# View current account settings\nGet-ADUser -Identity '%s' -Properties UserAccountControl, KerberosEncryptionType", c.SamAccountName))

	case "KERBEROAST":
		commands = append(commands, fmt.Sprintf("# Set strong password (replace with actual strong password)\n$SecurePassword = ConvertTo-SecureString 'NewStrongP@ssw0rd123!' -AsPlainText -Force\nSet-ADAccountPassword -Identity '%s' -NewPassword $SecurePassword -Reset", c.SamAccountName))
		commands = append(commands, fmt.Sprintf("# Enable AES256 encryption\nSet-ADUser -Identity '%s' -KerberosEncryptionType AES256", c.SamAccountName))
		commands = append(commands, fmt.Sprintf("# List all SPNs\nGet-ADUser -Identity '%s' -Properties ServicePrincipalNames | Select-Object -ExpandProperty ServicePrincipalNames", c.SamAccountName))
		if len(c.SPNs) > 0 {
			commands = append(commands, fmt.Sprintf("# Remove specific SPN (if not needed)\nSet-ADUser -Identity '%s' -ServicePrincipalNames @{Remove='%s'}", c.SamAccountName, c.SPNs[0]))
		}

	case "HVT":
		commands = append(commands, fmt.Sprintf("# View privileged group memberships\nGet-ADUser -Identity '%s' -Properties MemberOf | Select-Object -ExpandProperty MemberOf", c.SamAccountName))
		commands = append(commands, fmt.Sprintf("# Enable account auditing\nSet-ADUser -Identity '%s' -Replace @{adminCount=1}", c.SamAccountName))
		commands = append(commands, "# Enable advanced audit policy for this account\nauditpol /set /subcategory:\"User Account Management\" /success:enable /failure:enable")

	case "LOOT":
		commands = append(commands, fmt.Sprintf("# Clear description field\nSet-ADUser -Identity '%s' -Description $null", c.SamAccountName))
		commands = append(commands, fmt.Sprintf("# Clear info field\nSet-ADUser -Identity '%s' -Clear info", c.SamAccountName))
		commands = append(commands, fmt.Sprintf("# View all LDAP attributes\nGet-ADUser -Identity '%s' -Properties *", c.SamAccountName))

	case "RECON":
		if strings.Contains(c.SamAccountName, "\\") {
			shareName := strings.Split(c.SamAccountName, "\\")[1]
			commands = append(commands, fmt.Sprintf("# Review share permissions\nGet-SmbShareAccess -Name '%s'", shareName))
			commands = append(commands, fmt.Sprintf("# Remove Everyone access\nRevoke-SmbShareAccess -Name '%s' -AccountName 'Everyone' -Force", shareName))
			commands = append(commands, fmt.Sprintf("# Grant specific access\nGrant-SmbShareAccess -Name '%s' -AccountName 'DOMAIN\\SpecificGroup' -AccessRight Read -Force", shareName))
		}
	}

	return commands
}

// generateDetectionGuidance creates detection guidance
func generateDetectionGuidance(c krb.Candidate) []string {
	guidance := make([]string, 0)

	switch c.Type {
	case "ASREP":
		guidance = append(guidance, "Monitor Event ID 4768 (Kerberos TGT Request) with PreAuthType = 0")
		guidance = append(guidance, "Alert on multiple AS-REP requests from single source")
		guidance = append(guidance, "Sigma Rule: win_security_susp_kerberos_rc4.yml")
		guidance = append(guidance, "SIEM Query: EventCode=4768 AND PreAuthType=0")

	case "KERBEROAST":
		guidance = append(guidance, "Monitor Event ID 4769 (Kerberos Service Ticket Request)")
		guidance = append(guidance, "Alert on TGS requests with RC4 encryption (TicketEncryptionType=0x17)")
		guidance = append(guidance, "Look for unusual service ticket requests from non-service accounts")
		guidance = append(guidance, "Sigma Rule: win_security_kerberoasting.yml")
		guidance = append(guidance, "SIEM Query: EventCode=4769 AND TicketEncryptionType=0x17 AND ServiceName!='krbtgt'")

	case "HVT":
		guidance = append(guidance, "Monitor Event ID 4672 (Special Privileges Assigned to New Logon)")
		guidance = append(guidance, "Alert on privileged account logons from unusual locations")
		guidance = append(guidance, "Track Event ID 4624 (Successful Logon) for this account")
		guidance = append(guidance, "Enable advanced audit policy for privileged accounts")

	case "LOOT":
		guidance = append(guidance, "Monitor Event ID 5136 (Directory Service Object Modified)")
		guidance = append(guidance, "Alert on LDAP attribute modifications (Description, Info, Comment)")
		guidance = append(guidance, "Track Event ID 4662 (Operation Performed on Object)")
		guidance = append(guidance, "Implement DLP for credential patterns in LDAP")

	case "RECON":
		guidance = append(guidance, "Monitor Event ID 5140 (Network Share Accessed)")
		guidance = append(guidance, "Alert on unusual share access patterns")
		guidance = append(guidance, "Track Event ID 5145 (Network Share Object Checked for Access)")
		guidance = append(guidance, "Implement file access auditing on sensitive shares")
	}

	return guidance
}

// generateMermaidDiagram creates a Mermaid.js flowchart for an attack path
func generateMermaidDiagram(path reasoning.AttackPath) string {
	var sb strings.Builder
	sb.WriteString("graph LR\n")

	// Sanitize node IDs for Mermaid
	sanitize := func(s string) string {
		s = strings.ReplaceAll(s, ":", "_")
		s = strings.ReplaceAll(s, " ", "_")
		s = strings.ReplaceAll(s, ".", "_")
		s = strings.ReplaceAll(s, "/", "_")
		s = strings.ReplaceAll(s, "\\", "_")
		s = strings.ReplaceAll(s, "@", "_")
		s = strings.ReplaceAll(s, "-", "_")
		return s
	}

	// Style based on validation
	styleClass := "default"
	switch path.Validation {
	case "validated":
		styleClass = "validated"
	case "likely":
		styleClass = "likely"
	case "theoretical":
		styleClass = "theoretical"
	case "blocked":
		styleClass = "blocked"
	}

	// Generate nodes and edges
	for i, step := range path.Steps {
		fromID := sanitize(step.From)
		toID := sanitize(step.To)

		// Truncate long labels
		fromLabel := step.From
		if len(fromLabel) > 30 {
			fromLabel = fromLabel[:27] + "..."
		}
		toLabel := step.To
		if len(toLabel) > 30 {
			toLabel = toLabel[:27] + "..."
		}
		action := step.Action
		if len(action) > 40 {
			action = action[:37] + "..."
		}

		// Add nodes with labels
		if i == 0 {
			sb.WriteString(fmt.Sprintf("    %s[\"%s\"]:::%s\n", fromID, fromLabel, styleClass))
		}
		sb.WriteString(fmt.Sprintf("    %s[\"%s\"]:::%s\n", toID, toLabel, styleClass))

		// Add edge with action label
		sb.WriteString(fmt.Sprintf("    %s -->|%s| %s\n", fromID, action, toID))
	}

	// Add styling
	sb.WriteString("    classDef validated fill:#10b981,stroke:#059669,color:#fff\n")
	sb.WriteString("    classDef likely fill:#f59e0b,stroke:#d97706,color:#fff\n")
	sb.WriteString("    classDef theoretical fill:#8b5cf6,stroke:#7c3aed,color:#fff\n")
	sb.WriteString("    classDef blocked fill:#ef4444,stroke:#dc2626,color:#fff\n")
	sb.WriteString("    classDef default fill:#3b82f6,stroke:#2563eb,color:#fff\n")

	return sb.String()
}

// htmlTemplate is the HTML template for the professional report
const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Cold Relay Security Assessment Report - {{.Domain.Name}}</title>
    <script src="https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    <script>
        mermaid.initialize({ startOnLoad: true, theme: 'default', securityLevel: 'loose' });
    </script>
    <style>
        :root {
            --bg: #f4f6f9;
            --surface: #ffffff;
            --surface-alt: #f8fafc;
            --text: #111827;
            --muted: #6b7280;
            --border: #dbe2ea;
            --accent: #2563eb;
            --ok: #0f766e;
            --warn: #b45309;
            --risk: #b91c1c;
        }
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: "Inter", "Segoe UI", Roboto, Arial, sans-serif;
            line-height: 1.5;
            color: var(--text);
            background-color: var(--bg);
            font-size: 14px;
        }

        .container {
            max-width: 1100px;
            margin: 0 auto;
            padding: 40px 32px;
        }

        .header {
            margin-bottom: 40px;
            padding-bottom: 20px;
            border-bottom: 1px solid var(--border);
        }

        .header h1 {
            font-size: 28px;
            font-weight: 600;
            color: var(--text);
            margin-bottom: 6px;
            letter-spacing: -0.3px;
        }

        .header .subtitle {
            font-size: 12px;
            color: var(--muted);
            font-weight: 500;
            text-transform: uppercase;
            letter-spacing: 1px;
        }

        .header .meta {
            margin-top: 16px;
            font-size: 12px;
            color: var(--muted);
            display: flex;
            gap: 28px;
        }

        .header .meta span {
            display: flex;
            align-items: center;
            gap: 6px;
        }

        .header .meta strong {
            color: var(--text);
            font-weight: 500;
        }

        .section {
            margin-bottom: 40px;
        }

        .section h2 {
            color: var(--text);
            font-size: 16px;
            font-weight: 600;
            margin-bottom: 16px;
            letter-spacing: -0.2px;
        }

        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 12px;
            margin-bottom: 24px;
        }

        .summary-card {
            background: var(--surface);
            padding: 20px;
            border: 1px solid var(--border);
            border-radius: 8px;
        }

        .summary-card h3 {
            font-size: 11px;
            color: var(--muted);
            margin-bottom: 10px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            font-weight: 500;
        }

        .summary-card .value {
            font-size: 32px;
            font-weight: 600;
            color: var(--text);
            letter-spacing: -0.8px;
        }

        .domain-info {
            background: var(--surface);
            padding: 20px;
            border: 1px solid var(--border);
            border-radius: 8px;
            margin-bottom: 20px;
        }

        .domain-info table {
            width: 100%;
            border-collapse: collapse;
        }

        .domain-info td {
            padding: 10px 0;
            border-bottom: 1px solid var(--border);
            font-size: 13px;
        }

        .domain-info tr:last-child td {
            border-bottom: none;
        }

        .domain-info td:first-child {
            color: var(--muted);
            width: 180px;
            font-weight: 500;
        }

        .domain-info td:last-child {
            color: var(--text);
            font-weight: 500;
        }

        .findings-table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 20px;
            font-size: 13px;
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 8px;
            overflow: hidden;
        }

        .findings-table th,
        .findings-table td {
            padding: 12px 14px;
            text-align: left;
            border-bottom: 1px solid var(--border);
        }

        .findings-table th {
            background-color: var(--surface-alt);
            color: var(--muted);
            font-weight: 500;
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .findings-table td {
            color: var(--text);
        }

        .findings-table tr:last-child td {
            border-bottom: none;
        }

        .badge {
            display: inline-block;
            padding: 4px 10px;
            font-size: 11px;
            font-weight: 500;
            text-transform: uppercase;
            letter-spacing: 0.3px;
        }

        .badge-validated {
            color: var(--ok);
        }

        .badge-likely {
            color: var(--warn);
        }

        .badge-theoretical {
            color: #7c3aed;
        }

        .badge-blocked {
            color: var(--risk);
        }

        .badge-insufficient {
            color: var(--muted);
        }

        .severity-critical {
            color: #f87171;
            font-weight: 500;
        }

        .severity-high {
            color: #fb923c;
            font-weight: 500;
        }

        .severity-medium {
            color: #facc15;
            font-weight: 500;
        }

        .severity-low {
            color: #a3e635;
            font-weight: 500;
        }

        .severity-unknown {
            color: #737373;
            font-weight: 500;
        }

        .attack-path {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 12px;
        }

        .attack-path h4 {
            color: var(--text);
            margin-bottom: 12px;
            font-size: 14px;
            font-weight: 600;
        }

        .evidence-list,
        .blocker-list {
            margin-top: 12px;
            list-style: none;
        }

        .evidence-list li,
        .blocker-list li {
            margin-bottom: 6px;
            color: #334155;
            font-size: 13px;
            padding-left: 16px;
            position: relative;
        }

        .evidence-list li:before,
        .blocker-list li:before {
            content: "•";
            position: absolute;
            left: 0;
            color: #94a3b8;
        }

        .risk-insights {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 20px;
        }

        .risk-insights h3 {
            color: var(--text);
            margin-bottom: 12px;
            font-size: 14px;
            font-weight: 600;
        }

        .risk-insights ul {
            list-style: none;
        }

        .risk-insights li {
            margin-bottom: 8px;
            color: var(--text);
            font-size: 13px;
            padding-left: 16px;
            position: relative;
        }

        .risk-insights li:before {
            content: "•";
            position: absolute;
            left: 0;
            color: var(--accent);
        }

        .footer {
            margin-top: 48px;
            padding-top: 20px;
            border-top: 1px solid var(--border);
            text-align: center;
            color: var(--muted);
            font-size: 12px;
        }

        .footer p {
            margin-bottom: 6px;
        }

        .search-filter {
            margin-bottom: 20px;
            padding: 16px;
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 8px;
        }

        .search-filter input {
            width: 100%;
            padding: 10px 14px;
            border: 1px solid var(--border);
            border-radius: 6px;
            font-size: 14px;
            font-family: inherit;
        }

        .search-filter input:focus {
            outline: none;
            border-color: var(--accent);
        }

        .filter-buttons {
            display: flex;
            gap: 8px;
            margin-top: 12px;
            flex-wrap: wrap;
        }

        .filter-btn {
            padding: 6px 12px;
            border: 1px solid var(--border);
            background: var(--surface);
            border-radius: 6px;
            cursor: pointer;
            font-size: 12px;
            font-weight: 500;
            transition: all 0.2s;
        }

        .filter-btn:hover {
            background: var(--surface-alt);
        }

        .filter-btn.active {
            background: var(--accent);
            color: white;
            border-color: var(--accent);
        }

        .remediation-section {
            margin-top: 16px;
            padding: 16px;
            background: var(--surface-alt);
            border-radius: 6px;
            border-left: 3px solid var(--accent);
        }

        .remediation-section h5 {
            font-size: 13px;
            font-weight: 600;
            margin-bottom: 10px;
            color: var(--text);
        }

        .remediation-section ol {
            margin-left: 20px;
            font-size: 13px;
            color: var(--text);
        }

        .remediation-section li {
            margin-bottom: 6px;
        }

        .code-block {
            background: #1e293b;
            color: #e2e8f0;
            padding: 12px;
            border-radius: 6px;
            font-family: 'Consolas', 'Monaco', monospace;
            font-size: 12px;
            overflow-x: auto;
            margin-top: 8px;
            white-space: pre-wrap;
            word-wrap: break-word;
        }

        .detection-guidance {
            margin-top: 12px;
            padding: 12px;
            background: #fef3c7;
            border-left: 3px solid #f59e0b;
            border-radius: 6px;
        }

        .detection-guidance h5 {
            font-size: 13px;
            font-weight: 600;
            margin-bottom: 8px;
            color: #92400e;
        }

        .detection-guidance ul {
            list-style: none;
            font-size: 12px;
            color: #78350f;
        }

        .detection-guidance li {
            margin-bottom: 4px;
            padding-left: 16px;
            position: relative;
        }

        .detection-guidance li:before {
            content: "▸";
            position: absolute;
            left: 0;
            color: #92400e;
        }

        .mermaid-diagram {
            background: var(--surface);
            padding: 20px;
            border: 1px solid var(--border);
            border-radius: 8px;
            margin-bottom: 20px;
            overflow-x: auto;
        }

        .risk-score-card {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 24px;
            border-radius: 8px;
            text-align: center;
            margin-bottom: 20px;
        }

        .risk-score-card h3 {
            font-size: 14px;
            font-weight: 500;
            margin-bottom: 12px;
            opacity: 0.9;
        }

        .risk-score-card .score {
            font-size: 48px;
            font-weight: 700;
            letter-spacing: -2px;
        }

        .risk-score-card .score-label {
            font-size: 12px;
            margin-top: 8px;
            opacity: 0.8;
        }

        .collapsible {
            cursor: pointer;
            user-select: none;
        }

        .collapsible:hover {
            opacity: 0.8;
        }

        .collapsible-content {
            max-height: 0;
            overflow: hidden;
            transition: max-height 0.3s ease;
        }

        .collapsible-content.active {
            max-height: 2000px;
        }

        .export-btn {
            padding: 10px 20px;
            background: var(--accent);
            color: white;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            font-size: 14px;
            font-weight: 500;
            margin-right: 10px;
        }

        .export-btn:hover {
            opacity: 0.9;
        }

        .toc {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 30px;
        }

        .toc h3 {
            font-size: 14px;
            font-weight: 600;
            margin-bottom: 12px;
            color: var(--text);
        }

        .toc ul {
            list-style: none;
        }

        .toc li {
            margin-bottom: 8px;
        }

        .toc a {
            color: var(--accent);
            text-decoration: none;
            font-size: 13px;
            transition: color 0.2s;
        }

        .toc a:hover {
            color: #1d4ed8;
            text-decoration: underline;
        }

        .executive-summary {
            background: linear-gradient(135deg, #1e293b 0%, #334155 100%);
            color: white;
            padding: 32px;
            border-radius: 8px;
            margin-bottom: 30px;
        }

        .executive-summary h2 {
            color: white;
            margin-bottom: 20px;
        }

        .exec-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }

        .exec-card {
            background: rgba(255, 255, 255, 0.1);
            padding: 16px;
            border-radius: 6px;
            border: 1px solid rgba(255, 255, 255, 0.2);
        }

        .exec-card h4 {
            font-size: 12px;
            font-weight: 500;
            margin-bottom: 8px;
            opacity: 0.9;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .exec-card .value {
            font-size: 24px;
            font-weight: 600;
            margin-bottom: 4px;
        }

        .exec-card ul {
            list-style: none;
            font-size: 13px;
            line-height: 1.6;
        }

        .exec-card li {
            margin-bottom: 6px;
            padding-left: 12px;
            position: relative;
        }

        .exec-card li:before {
            content: "▸";
            position: absolute;
            left: 0;
            opacity: 0.7;
        }

        .chart-container {
            background: var(--surface);
            padding: 20px;
            border: 1px solid var(--border);
            border-radius: 8px;
            margin-bottom: 20px;
        }

        .chart-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }

        .chart-wrapper {
            position: relative;
            height: 300px;
        }

        .severity-matrix {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 12px;
            margin-top: 20px;
        }

        .severity-cell {
            padding: 20px;
            border-radius: 6px;
            text-align: center;
            color: white;
            font-weight: 600;
        }

        .severity-cell.critical {
            background: linear-gradient(135deg, #dc2626 0%, #991b1b 100%);
        }

        .severity-cell.high {
            background: linear-gradient(135deg, #ea580c 0%, #c2410c 100%);
        }

        .severity-cell.medium {
            background: linear-gradient(135deg, #d97706 0%, #b45309 100%);
        }

        .severity-cell.low {
            background: linear-gradient(135deg, #65a30d 0%, #4d7c0f 100%);
        }

        .severity-cell .count {
            font-size: 32px;
            display: block;
            margin-bottom: 4px;
        }

        .severity-cell .label {
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            opacity: 0.9;
        }

        .json-output {
            background: #1e293b;
            color: #e2e8f0;
            padding: 20px;
            border-radius: 8px;
            overflow-x: auto;
            font-family: 'Consolas', 'Monaco', monospace;
            font-size: 12px;
            line-height: 1.6;
            max-height: 600px;
            overflow-y: auto;
            border: 1px solid #334155;
        }

        .json-output pre {
            margin: 0;
            white-space: pre-wrap;
            word-wrap: break-word;
        }

        .page-break {
            page-break-after: always;
        }

        @media print {
            .container { padding: 20px; }
            .search-filter, .filter-buttons, .export-btn { display: none; }
            .page-break { page-break-after: always; }
            .json-output { max-height: none; page-break-inside: avoid; }
            @page { margin: 2cm; }
            .header { page-break-after: avoid; }
            .executive-summary { page-break-inside: avoid; }
            .toc { page-break-after: always; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Cold Relay</h1>
            <div class="subtitle">Active Directory Security Assessment Report</div>
            <div class="meta">
                <span><strong>Target Domain:</strong> {{.Domain.Name}}</span>
                <span><strong>Assessment Date:</strong> {{.GeneratedAt}}</span>
                <span><strong>Report Version:</strong> {{.SchemaVersion}}</span>
            </div>
            <div style="margin-top: 16px;">
                <button class="export-btn" onclick="exportToJSON()">Export Filtered JSON</button>
                <button class="export-btn" onclick="window.print()">Print / Save PDF</button>
            </div>
        </div>

        <!-- Table of Contents -->
        <div class="toc">
            <h3>Table of Contents</h3>
            <ul>
                <li><a href="#executive-summary">1. Executive Summary</a></li>
                <li><a href="#risk-overview">2. Risk Overview & Metrics</a></li>
                <li><a href="#domain-info">3. Domain Information</a></li>
                <li><a href="#severity-distribution">4. Severity Distribution</a></li>
                <li><a href="#risk-insights">5. Risk Insights & Attack Chain</a></li>
                <li><a href="#confirmed-findings">6. Confirmed Findings</a></li>
                <li><a href="#review-findings">7. Findings Requiring Verification</a></li>
                <li><a href="#attack-paths">8. Attack Paths</a></li>
                <li><a href="#json-output">9. Full JSON Output</a></li>
            </ul>
        </div>

        <!-- Executive Summary -->
        <div id="executive-summary" class="executive-summary">
            <h2>Executive Summary</h2>
            <p style="margin-bottom: 20px; line-height: 1.6; opacity: 0.95;">
                This assessment identified <strong>{{.Summary.HighRiskObjects}} security findings</strong> across the {{.Domain.Name}} Active Directory environment. 
                The overall risk score is <strong>{{.OverallRiskScore}}/100 ({{.RiskLevel}})</strong>, indicating 
                {{if ge .OverallRiskScore 80}}immediate action is required to prevent potential domain compromise.
                {{else if ge .OverallRiskScore 60}}significant security gaps that should be addressed promptly.
                {{else if ge .OverallRiskScore 40}}moderate security concerns requiring attention.
                {{else}}an acceptable security posture with minor improvements recommended.{{end}}
            </p>

            <div class="exec-grid">
                <div class="exec-card">
                    <h4>Findings by Severity</h4>
                    <div class="value">{{.ExecutiveSummary.CriticalFindings}}</div>
                    <div style="font-size: 12px; opacity: 0.8;">Critical</div>
                    <div class="value" style="font-size: 20px; margin-top: 8px;">{{.ExecutiveSummary.HighFindings}}</div>
                    <div style="font-size: 12px; opacity: 0.8;">High</div>
                    <div class="value" style="font-size: 18px; margin-top: 8px;">{{.ExecutiveSummary.MediumFindings}}</div>
                    <div style="font-size: 12px; opacity: 0.8;">Medium</div>
                </div>

                <div class="exec-card">
                    <h4>Top Risks Identified</h4>
                    <ul>
                        {{range .ExecutiveSummary.TopRisks}}
                        <li>{{.}}</li>
                        {{else}}
                        <li>No critical risks identified</li>
                        {{end}}
                    </ul>
                </div>

                <div class="exec-card">
                    <h4>Quick Wins</h4>
                    <ul>
                        {{range .ExecutiveSummary.QuickWins}}
                        <li>{{.}}</li>
                        {{else}}
                        <li>Continue current security practices</li>
                        {{end}}
                    </ul>
                </div>

                <div class="exec-card">
                    <h4>Remediation Estimate</h4>
                    <div style="font-size: 14px; margin-top: 8px; line-height: 1.6;">
                        <strong>Effort:</strong> {{.ExecutiveSummary.EstimatedEffort}}
                    </div>
                    <div style="font-size: 13px; margin-top: 12px; line-height: 1.5; opacity: 0.9;">
                        {{.ExecutiveSummary.ComplianceImpact}}
                    </div>
                </div>
            </div>
        </div>

        <div class="page-break"></div>

        <!-- Risk Overview & Metrics -->
        <div id="risk-overview" class="section">
            <h2>Risk Overview & Metrics</h2>
            
            <div class="risk-score-card">
                <h3>Overall Risk Score</h3>
                <div class="score">{{.OverallRiskScore}}</div>
                <div class="score-label">{{.RiskLevel}} RISK</div>
            </div>

            <div class="chart-grid">
                <div class="chart-container">
                    <h3 style="font-size: 14px; margin-bottom: 16px; font-weight: 600;">Severity Distribution</h3>
                    <div class="chart-wrapper">
                        <canvas id="severityChart"></canvas>
                    </div>
                </div>

                <div class="chart-container">
                    <h3 style="font-size: 14px; margin-bottom: 16px; font-weight: 600;">Finding Types</h3>
                    <div class="chart-wrapper">
                        <canvas id="typeChart"></canvas>
                    </div>
                </div>
            </div>

            <div class="chart-container">
                <h3 style="font-size: 14px; margin-bottom: 16px; font-weight: 600;">Validation Status</h3>
                <div class="chart-wrapper">
                    <canvas id="validationChart"></canvas>
                </div>
            </div>
        </div>

        <!-- Domain Information -->
        <div id="domain-info" class="section">
            <h2>Domain Information</h2>
            <div class="summary-grid">
                <div class="summary-card">
                    <h3>Total Users</h3>
                    <div class="value">{{.Summary.TotalUsers}}</div>
                </div>
                <div class="summary-card">
                    <h3>AS-REP Candidates</h3>
                    <div class="value">{{.Summary.ASREPCandidates}}</div>
                </div>
                <div class="summary-card">
                    <h3>Kerberoast Candidates</h3>
                    <div class="value">{{.Summary.KerberoastCandidates}}</div>
                </div>
                <div class="summary-card">
                    <h3>High Value Targets</h3>
                    <div class="value">{{.Summary.HVTCandidates}}</div>
                </div>
                <div class="summary-card">
                    <h3>Total Groups</h3>
                    <div class="value">{{.Summary.TotalGroups}}</div>
                </div>
                <div class="summary-card">
                    <h3>High Risk Objects</h3>
                    <div class="value">{{.Summary.HighRiskObjects}}</div>
                </div>
            </div>

            <div class="domain-info">
                <table>
                    <tr>
                        <td>Domain Name</td>
                        <td>{{.Domain.Name}}</td>
                    </tr>
                    <tr>
                        <td>Distinguished Name</td>
                        <td>{{.Domain.DN}}</td>
                    </tr>
                    <tr>
                        <td>Functional Level</td>
                        <td>{{.Domain.FunctionalLevel}}</td>
                    </tr>
                    <tr>
                        <td>OS Version</td>
                        <td>{{.Domain.OS}}</td>
                    </tr>
                </table>
            </div>
        </div>

        <!-- Severity Distribution Matrix -->
        <div id="severity-distribution" class="section">
            <h2>Severity Distribution Matrix</h2>
            <div class="severity-matrix">
                <div class="severity-cell critical">
                    <span class="count">{{.ExecutiveSummary.CriticalFindings}}</span>
                    <span class="label">Critical</span>
                </div>
                <div class="severity-cell high">
                    <span class="count">{{.ExecutiveSummary.HighFindings}}</span>
                    <span class="label">High</span>
                </div>
                <div class="severity-cell medium">
                    <span class="count">{{.ExecutiveSummary.MediumFindings}}</span>
                    <span class="label">Medium</span>
                </div>
                <div class="severity-cell low">
                    <span class="count">{{.ExecutiveSummary.LowFindings}}</span>
                    <span class="label">Low</span>
                </div>
            </div>
        </div>

        <!-- Validation Status Summary -->
        <div class="section">
            <h2>Validation Status Summary</h2>
            <div class="summary-grid">
                {{range $status, $count := .ValidationCounts}}
                <div class="summary-card">
                    <h3>{{$status}}</h3>
                    <div class="value">{{$count}}</div>
                </div>
                {{end}}
            </div>
        </div>

        <!-- Risk Insights -->
        {{if .RiskInsights}}
        <div id="risk-insights" class="section">
            <h2>Risk Insights & Attack Chain</h2>
            <div class="risk-insights">
                <h3>Key Findings</h3>
                <ul>
                    {{range .RiskInsights}}
                    <li>{{.}}</li>
                    {{end}}
                </ul>
            </div>
        </div>
        {{end}}

        {{if .HeuristicAdvisories}}
        <div class="section">
            <h2>Double-Verify Advisories</h2>
            <div class="risk-insights">
                <h3>Heuristic Findings Requiring Confirmation</h3>
                <ul>
                    {{range .HeuristicAdvisories}}
                    <li>{{.}}</li>
                    {{end}}
                </ul>
            </div>
        </div>
        {{end}}

        <!-- Detailed Findings -->
        <div id="confirmed-findings" class="section">
            <h2>Confirmed Findings (Observed Evidence)</h2>
            
            <!-- Search and Filter -->
            <div class="search-filter">
                <input type="text" id="searchInput" placeholder="Search by account name, type, or evidence..." onkeyup="filterFindings()">
                <div class="filter-buttons">
                    <button class="filter-btn active" data-filter="all" onclick="setFilter('all')">All</button>
                    <button class="filter-btn" data-filter="ASREP" onclick="setFilter('ASREP')">AS-REP</button>
                    <button class="filter-btn" data-filter="KERBEROAST" onclick="setFilter('KERBEROAST')">Kerberoast</button>
                    <button class="filter-btn" data-filter="HVT" onclick="setFilter('HVT')">HVT</button>
                    <button class="filter-btn" data-filter="LOOT" onclick="setFilter('LOOT')">Loot</button>
                    <button class="filter-btn" data-filter="RECON" onclick="setFilter('RECON')">Recon</button>
                </div>
            </div>

            {{if .ConfirmedCandidates}}
            <table class="findings-table" id="confirmedTable">
                <thead>
                    <tr>
                        <th>Account</th>
                        <th>Type</th>
                        <th>Score</th>
                        <th>Severity</th>
                        <th>Validation</th>
                        <th>Evidence</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    {{range .ConfirmedCandidates}}
                    <tr class="finding-row" data-type="{{.Type}}" data-account="{{.SamAccountName}}" data-evidence="{{range .Evidence}}{{.}} {{end}}">
                        <td><strong>{{.SamAccountName}}</strong></td>
                        <td>{{.Type}}</td>
                        <td>{{.Score}}</td>
                        <td><span class="badge severity-{{.Severity | toLower}}">{{.Severity}}</span></td>
                        <td><span class="badge badge-{{.Validation | toLower}}">{{.Validation}}</span></td>
                        <td>{{range .Evidence}}{{.}}<br>{{end}}</td>
                        <td>
                            <button class="filter-btn" onclick="toggleDetails('confirmed-{{.SamAccountName}}')">Show Details</button>
                        </td>
                    </tr>
                    <tr id="confirmed-{{.SamAccountName}}" style="display:none;">
                        <td colspan="7">
                            {{if .RemediationSteps}}
                            <div class="remediation-section">
                                <h5>Remediation Steps</h5>
                                <ol>
                                    {{range .RemediationSteps}}
                                    <li>{{.}}</li>
                                    {{end}}
                                </ol>
                            </div>
                            {{end}}
                            
                            {{if .PowerShellCommands}}
                            <div class="remediation-section">
                                <h5>PowerShell Commands</h5>
                                {{range .PowerShellCommands}}
                                <div class="code-block">{{.}}</div>
                                {{end}}
                            </div>
                            {{end}}
                            
                            {{if .DetectionGuidance}}
                            <div class="detection-guidance">
                                <h5>Detection & Monitoring</h5>
                                <ul>
                                    {{range .DetectionGuidance}}
                                    <li>{{.}}</li>
                                    {{end}}
                                </ul>
                            </div>
                            {{end}}
                            
                            {{if .Blockers}}
                            <div class="remediation-section">
                                <h5>Blockers</h5>
                                <ul>
                                    {{range .Blockers}}
                                    <li>{{.}}</li>
                                    {{end}}
                                </ul>
                            </div>
                            {{end}}
                            
                            {{if .NextActions}}
                            <div class="remediation-section">
                                <h5>Next Actions</h5>
                                <ul>
                                    {{range .NextActions}}
                                    <li>{{.}}</li>
                                    {{end}}
                                </ul>
                            </div>
                            {{end}}
                        </td>
                    </tr>
                    {{end}}
                </tbody>
            </table>
            {{else}}
            <div class="risk-insights"><ul><li>No fully confirmed findings in this run.</li></ul></div>
            {{end}}
        </div>

        <div id="review-findings" class="section">
            <h2>Needs Verification (Heuristic / Partial Evidence)</h2>
            {{if .ReviewCandidates}}
            <table class="findings-table">
                <thead>
                    <tr>
                        <th>Account</th>
                        <th>Type</th>
                        <th>Score</th>
                        <th>Severity</th>
                        <th>Validation</th>
                        <th>Evidence</th>
                        <th>Blockers</th>
                        <th>Next Actions</th>
                    </tr>
                </thead>
                <tbody>
                    {{range .ReviewCandidates}}
                    <tr>
                        <td><strong>{{.SamAccountName}}</strong></td>
                        <td>{{.Type}}</td>
                        <td>{{.Score}}</td>
                        <td><span class="badge severity-{{.Severity | toLower}}">{{.Severity}}</span></td>
                        <td><span class="badge badge-{{.Validation | toLower}}">{{.Validation}}</span></td>
                        <td>{{range .Evidence}}{{.}}<br>{{end}}</td>
                        <td>{{range .Blockers}}{{.}}<br>{{end}}</td>
                        <td>{{range .NextActions}}{{.}}<br>{{end}}</td>
                    </tr>
                    {{end}}
                </tbody>
            </table>
            {{else}}
            <div class="risk-insights"><ul><li>No heuristic findings requiring additional verification.</li></ul></div>
            {{end}}
        </div>

        <!-- Attack Paths -->
        {{if .AttackPaths}}
        <div id="attack-paths" class="section">
            <h2>Attack Paths with Visual Diagrams</h2>
            {{range $index, $path := .AttackPaths}}
            <div class="attack-path">
                <h4><span class="badge badge-{{$path.Validation | toLower}}">{{$path.Validation}}</span> <span class="badge severity-{{$path.Severity | toLower}}">{{$path.Severity}}</span> {{$path.Title}}</h4>
                
                {{if lt $index (len $.MermaidDiagrams)}}
                <div class="mermaid-diagram">
                    <pre class="mermaid">{{index $.MermaidDiagrams $index}}</pre>
                </div>
                {{end}}
                
                {{if $path.Steps}}
                <strong>Attack Steps:</strong>
                <ul class="evidence-list">
                    {{range $path.Steps}}
                    <li>{{.}}</li>
                    {{end}}
                </ul>
                {{end}}
                {{if $path.Evidence}}
                <strong>Evidence:</strong>
                <ul class="evidence-list">
                    {{range $path.Evidence}}
                    <li>{{.}}</li>
                    {{end}}
                </ul>
                {{end}}
                {{if $path.Blockers}}
                <strong>Blockers:</strong>
                <ul class="blocker-list">
                    {{range $path.Blockers}}
                    <li>{{.}}</li>
                    {{end}}
                </ul>
                {{end}}
            </div>
            {{end}}
        </div>
        {{end}}

        <div class="page-break"></div>

        <!-- Full JSON Output -->
        <div id="json-output" class="section">
            <h2>Full JSON Output</h2>
            <p style="margin-bottom: 16px; color: var(--muted); font-size: 13px;">
                Complete assessment results in JSON format. This output can be used for integration with other security tools, 
                custom analysis, or archival purposes.
            </p>
            <div class="json-output">
                <pre>{{.FullJSONOutput}}</pre>
            </div>
        </div>

        <div class="footer">
            <p>Generated by Cold Relay v1.0.0 | For authorized security testing only</p>
            <p>This report contains sensitive security information. Handle with appropriate care.</p>
        </div>
    </div>

    <script>
        let currentFilter = 'all';

        // Initialize charts
        document.addEventListener('DOMContentLoaded', function() {
            initCharts();
        });

        function initCharts() {
            // Severity Distribution Chart
            const severityCtx = document.getElementById('severityChart');
            if (severityCtx) {
                new Chart(severityCtx, {
                    type: 'doughnut',
                    data: {
                        labels: [
                            {{range $key, $value := .SeverityDistribution}}'{{$key}}',{{end}}
                        ],
                        datasets: [{
                            data: [
                                {{range $key, $value := .SeverityDistribution}}{{$value}},{{end}}
                            ],
                            backgroundColor: [
                                '#ef4444', // Critical/High
                                '#f59e0b', // Medium
                                '#10b981', // Low
                                '#6b7280'  // Unknown
                            ],
                            borderWidth: 2,
                            borderColor: '#ffffff'
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {
                            legend: {
                                position: 'bottom',
                                labels: {
                                    padding: 15,
                                    font: { size: 12 }
                                }
                            }
                        }
                    }
                });
            }

            // Type Distribution Chart
            const typeCtx = document.getElementById('typeChart');
            if (typeCtx) {
                new Chart(typeCtx, {
                    type: 'bar',
                    data: {
                        labels: [
                            {{range $key, $value := .TypeDistribution}}'{{$key}}',{{end}}
                        ],
                        datasets: [{
                            label: 'Findings',
                            data: [
                                {{range $key, $value := .TypeDistribution}}{{$value}},{{end}}
                            ],
                            backgroundColor: '#2563eb',
                            borderRadius: 6
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {
                            legend: { display: false }
                        },
                        scales: {
                            y: {
                                beginAtZero: true,
                                ticks: { stepSize: 1 }
                            }
                        }
                    }
                });
            }

            // Validation Status Chart
            const validationCtx = document.getElementById('validationChart');
            if (validationCtx) {
                new Chart(validationCtx, {
                    type: 'bar',
                    data: {
                        labels: [
                            {{range $key, $value := .ValidationCounts}}'{{$key}}',{{end}}
                        ],
                        datasets: [{
                            label: 'Count',
                            data: [
                                {{range $key, $value := .ValidationCounts}}{{$value}},{{end}}
                            ],
                            backgroundColor: [
                                '#10b981', // validated
                                '#f59e0b', // likely
                                '#8b5cf6', // theoretical
                                '#ef4444', // blocked
                                '#6b7280'  // insufficient
                            ],
                            borderRadius: 6
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        indexAxis: 'y',
                        plugins: {
                            legend: { display: false }
                        },
                        scales: {
                            x: {
                                beginAtZero: true,
                                ticks: { stepSize: 1 }
                            }
                        }
                    }
                });
            }
        }

        function setFilter(filter) {
            currentFilter = filter;
            
            // Update button states
            document.querySelectorAll('.filter-btn[data-filter]').forEach(btn => {
                btn.classList.remove('active');
                if (btn.getAttribute('data-filter') === filter) {
                    btn.classList.add('active');
                }
            });
            
            filterFindings();
        }

        function filterFindings() {
            const searchTerm = document.getElementById('searchInput').value.toLowerCase();
            const rows = document.querySelectorAll('.finding-row');
            
            rows.forEach(row => {
                const type = row.getAttribute('data-type');
                const account = row.getAttribute('data-account').toLowerCase();
                const evidence = row.getAttribute('data-evidence').toLowerCase();
                
                const matchesFilter = currentFilter === 'all' || type === currentFilter;
                const matchesSearch = searchTerm === '' || 
                                     account.includes(searchTerm) || 
                                     type.toLowerCase().includes(searchTerm) ||
                                     evidence.includes(searchTerm);
                
                if (matchesFilter && matchesSearch) {
                    row.style.display = '';
                    // Also hide the details row if it exists
                    const detailsRow = row.nextElementSibling;
                    if (detailsRow && detailsRow.id.startsWith('confirmed-')) {
                        detailsRow.style.display = 'none';
                    }
                } else {
                    row.style.display = 'none';
                    // Also hide the details row
                    const detailsRow = row.nextElementSibling;
                    if (detailsRow && detailsRow.id.startsWith('confirmed-')) {
                        detailsRow.style.display = 'none';
                    }
                }
            });
        }

        function toggleDetails(id) {
            const detailsRow = document.getElementById(id);
            if (detailsRow) {
                if (detailsRow.style.display === 'none') {
                    detailsRow.style.display = '';
                } else {
                    detailsRow.style.display = 'none';
                }
            }
        }

        function exportToJSON() {
            // Collect visible findings data
            const findings = [];
            document.querySelectorAll('.finding-row').forEach(row => {
                if (row.style.display !== 'none') {
                    findings.push({
                        account: row.getAttribute('data-account'),
                        type: row.getAttribute('data-type'),
                        evidence: row.getAttribute('data-evidence')
                    });
                }
            });
            
            const data = {
                domain: '{{.Domain.Name}}',
                generated: '{{.GeneratedAt}}',
                risk_score: {{.OverallRiskScore}},
                findings: findings
            };
            
            const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'cold-relay-filtered-results.json';
            a.click();
            URL.revokeObjectURL(url);
        }

        // Initialize Mermaid
        if (typeof mermaid !== 'undefined') {
            mermaid.initialize({ startOnLoad: true });
        }
    </script>
</body>
</html>
`
