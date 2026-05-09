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
	EvidenceHighlights   []string
	ValidationCounts     map[string]int
	MermaidDiagrams      []string
	SeverityDistribution map[string]int
	TypeDistribution     map[string]int
	ExecutiveSummary     ExecutiveSummary
	FullJSONOutput       string
}

// ExecutiveSummary provides high-level overview for management
type ExecutiveSummary struct {
	TopRisks  []string
	QuickWins []string
}

// CandidateReport formats a candidate for the report
type CandidateReport struct {
	SamAccountName     string
	Type               string
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

	// Marshal full JSON output
	jsonBytes, _ := json.MarshalIndent(results, "", "  ")
	data.FullJSONOutput = string(jsonBytes)

	// Convert candidates with enhanced remediation
	for _, c := range results.Candidates {
		candidate := CandidateReport{
			SamAccountName:     c.SamAccountName,
			Type:               c.Type,
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

	// Evidence highlights section: useful even if confirmed candidate list is empty.
	if results.Advanced.Pwned {
		data.EvidenceHighlights = append(data.EvidenceHighlights, "Administrative SMB share access was confirmed.")
	}
	if n := len(results.Advanced.SensitiveFiles); n > 0 {
		data.EvidenceHighlights = append(data.EvidenceHighlights, fmt.Sprintf("Sensitive SMB file findings collected: %d.", n))
	}
	if results.ControlPlane != nil {
		aclEdges := 0
		for _, e := range results.ControlPlane.Edges {
			if strings.EqualFold(e.SourceModule, "ntsecuritydescriptor") {
				aclEdges++
			}
		}
		if aclEdges > 0 {
			data.EvidenceHighlights = append(data.EvidenceHighlights, fmt.Sprintf("ACL control edges parsed from nTSecurityDescriptor: %d.", aclEdges))
		}
		if len(results.ControlPlane.Coverage) > 0 {
			data.EvidenceHighlights = append(data.EvidenceHighlights, fmt.Sprintf("Coverage gaps explicitly tracked: %d.", len(results.ControlPlane.Coverage)))
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
  <title>Cold Relay Report - {{.Domain.Name}}</title>
  <style>
    :root {
      --bg: #f6f8fb;
      --surface: #ffffff;
      --border: #d6dbe3;
      --text: #111827;
      --muted: #6b7280;
      --accent: #1f4e79;
      --ok: #0f766e;
      --warn: #9a6700;
      --danger: #b42318;
    }
    * { box-sizing: border-box; }
    body { margin: 0; font-family: "Segoe UI", Arial, sans-serif; color: var(--text); background: var(--bg); }
    .container { max-width: 1080px; margin: 0 auto; padding: 28px; }
    .card { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 18px; margin-bottom: 16px; }
    h1 { margin: 0 0 6px; font-size: 28px; font-weight: 600; letter-spacing: -0.2px; }
    h2 { margin: 0 0 12px; font-size: 17px; font-weight: 600; color: var(--accent); }
    p, li, td, th { font-size: 13px; line-height: 1.5; }
    .meta { color: var(--muted); display: flex; gap: 20px; flex-wrap: wrap; margin-top: 8px; }
    .meta strong { color: var(--text); }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: 10px; }
    .kpi { border: 1px solid var(--border); border-radius: 6px; padding: 12px; background: #fbfcfe; }
    .kpi .k { color: var(--muted); font-size: 11px; text-transform: uppercase; }
    .kpi .v { margin-top: 4px; font-size: 22px; font-weight: 600; }
    .table { width: 100%; border-collapse: collapse; border: 1px solid var(--border); }
    .table th, .table td { padding: 10px; text-align: left; border-bottom: 1px solid var(--border); vertical-align: top; }
    .table th { background: #f3f6fb; color: #334155; font-size: 11px; text-transform: uppercase; letter-spacing: 0.4px; }
    .pill { padding: 2px 8px; border: 1px solid var(--border); border-radius: 999px; font-size: 11px; display: inline-block; }
    .validated { color: var(--ok); }
    .likely, .theoretical { color: var(--warn); }
    .blocked, .insufficient_visibility { color: var(--danger); }
    .mono { font-family: Consolas, Monaco, monospace; white-space: pre-wrap; background: #0f172a; color: #e2e8f0; padding: 12px; border-radius: 6px; max-height: 420px; overflow: auto; }
    .json-box { max-height: 260px; overflow: auto; }
    .empty { color: var(--muted); }
    @media print { .container { padding: 10px; } }
  </style>
</head>
<body>
  <div class="container">
    <div class="card">
      <h1>Cold Relay</h1>
      <p style="margin:0;color:var(--muted);">Active Directory Security Assessment Report</p>
      <div class="meta">
        <span><strong>Target Domain:</strong> {{.Domain.Name}}</span>
        <span><strong>Assessment Date:</strong> {{.GeneratedAt}}</span>
        <span><strong>Report Version:</strong> {{.SchemaVersion}}</span>
      </div>
    </div>

    <div class="card">
      <h2>Executive Summary</h2>
      <p>
        This report prioritizes observed evidence and verification gaps. It intentionally avoids percentage-based scoring.
        Findings are separated into confirmed evidence and items requiring additional validation.
      </p>
      <div class="grid" style="margin-top:12px;">
        <div class="kpi"><div class="k">Total Users</div><div class="v">{{.Summary.TotalUsers}}</div></div>
        <div class="kpi"><div class="k">AS-REP Candidates</div><div class="v">{{.Summary.ASREPCandidates}}</div></div>
        <div class="kpi"><div class="k">Kerberoast Candidates</div><div class="v">{{.Summary.KerberoastCandidates}}</div></div>
        <div class="kpi"><div class="k">High Value Targets</div><div class="v">{{.Summary.HVTCandidates}}</div></div>
        <div class="kpi"><div class="k">High Risk Objects</div><div class="v">{{.Summary.HighRiskObjects}}</div></div>
      </div>
    </div>

    <div class="card">
      <h2>Observed Evidence Highlights</h2>
      {{if .EvidenceHighlights}}
      <ul>
        {{range .EvidenceHighlights}}<li>{{.}}</li>{{end}}
      </ul>
      {{else}}
      <p class="empty">No direct high-confidence evidence highlights were produced in this run.</p>
      {{end}}
    </div>

    <div class="card">
      <h2>Top Risks Identified</h2>
      {{if .ExecutiveSummary.TopRisks}}
      <ul>{{range .ExecutiveSummary.TopRisks}}<li>{{.}}</li>{{end}}</ul>
      {{else}}
      <p class="empty">No top-risk statements generated from current run data.</p>
      {{end}}
      <h2 style="margin-top:16px;">Quick Wins</h2>
      {{if .ExecutiveSummary.QuickWins}}
      <ul>{{range .ExecutiveSummary.QuickWins}}<li>{{.}}</li>{{end}}</ul>
      {{else}}
      <p class="empty">No quick-win actions generated.</p>
      {{end}}
    </div>

    <div class="card">
      <h2>Validation Status Summary</h2>
      <div class="grid">
        {{range $status, $count := .ValidationCounts}}
        <div class="kpi">
          <div class="k">{{$status}}</div>
          <div class="v">{{$count}}</div>
        </div>
        {{end}}
      </div>
    </div>

    <div class="card">
      <h2>Confirmed Findings (Observed Evidence)</h2>
      {{if .ConfirmedCandidates}}
      <table class="table">
        <thead><tr><th>Account</th><th>Type</th><th>Validation</th><th>Evidence</th><th>Next Actions</th></tr></thead>
        <tbody>
        {{range .ConfirmedCandidates}}
          <tr>
            <td><strong>{{.SamAccountName}}</strong></td>
            <td>{{.Type}}</td>
            <td><span class="pill {{.Validation | toLower}}">{{.Validation}}</span></td>
            <td>{{range .Evidence}}{{.}}<br>{{end}}</td>
            <td>{{range .NextActions}}{{.}}<br>{{end}}</td>
          </tr>
        {{end}}
        </tbody>
      </table>
      {{else}}
      <p class="empty">No fully confirmed candidate findings in this run.</p>
      {{end}}
    </div>

    <div class="card">
      <h2>Findings Requiring Verification</h2>
      {{if .ReviewCandidates}}
      <table class="table">
        <thead><tr><th>Account</th><th>Type</th><th>Validation</th><th>Evidence</th><th>Blockers</th><th>Next Actions</th></tr></thead>
        <tbody>
        {{range .ReviewCandidates}}
          <tr>
            <td><strong>{{.SamAccountName}}</strong></td>
            <td>{{.Type}}</td>
            <td><span class="pill {{.Validation | toLower}}">{{.Validation}}</span></td>
            <td>{{range .Evidence}}{{.}}<br>{{end}}</td>
            <td>{{range .Blockers}}{{.}}<br>{{end}}</td>
            <td>{{range .NextActions}}{{.}}<br>{{end}}</td>
          </tr>
        {{end}}
        </tbody>
      </table>
      {{else}}
      <p class="empty">No heuristic findings requiring additional verification.</p>
      {{end}}
    </div>

    <div class="card">
      <h2>Attack Paths</h2>
      {{if .AttackPaths}}
      {{range .AttackPaths}}
      <div style="border:1px solid var(--border);border-radius:6px;padding:12px;margin-bottom:10px;">
        <p style="margin:0 0 8px;"><strong>{{.Title}}</strong> — <span class="pill {{.Validation | toLower}}">{{.Validation}}</span></p>
        {{if .Steps}}<p><strong>Steps</strong><br>{{range .Steps}}{{.}}<br>{{end}}</p>{{end}}
        {{if .Evidence}}<p><strong>Evidence</strong><br>{{range .Evidence}}{{.}}<br>{{end}}</p>{{end}}
        {{if .Blockers}}<p><strong>Blockers</strong><br>{{range .Blockers}}{{.}}<br>{{end}}</p>{{end}}
      </div>
      {{end}}
      {{else}}
      <p class="empty">No attack paths generated in this run.</p>
      {{end}}
    </div>

    <div class="card">
      <h2>results.json</h2>
      <p class="empty" style="margin-top:0;">Full raw output (scroll inside this box).</p>
      <div class="mono json-box">{{.FullJSONOutput}}</div>
    </div>

  </div>
</body>
</html>
`
