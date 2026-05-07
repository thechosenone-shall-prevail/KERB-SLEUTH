package output

import (
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ReportData holds the data for the HTML report template
type ReportData struct {
	GeneratedAt      string
	SchemaVersion    string
	Domain           DomainInfo
	Summary          Summary
	Candidates       []CandidateReport
	AttackPaths      []AttackPathReport
	RiskInsights     []string
	ValidationCounts map[string]int
}

// CandidateReport formats a candidate for the report
type CandidateReport struct {
	SamAccountName string
	Type           string
	Score          int
	Validation     string
	Severity       string
	Reasons        []string
	Evidence       []string
	Blockers       []string
	NextActions    []string
	SPNs           []string
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
		GeneratedAt:      time.Now().Format("2006-01-02 15:04:05 MST"),
		SchemaVersion:    results.SchemaVersion,
		Domain:           results.Domain,
		Summary:          results.Summary,
		RiskInsights:     results.RiskInsights,
		ValidationCounts: make(map[string]int),
	}

	// Convert candidates
	for _, c := range results.Candidates {
		candidate := CandidateReport{
			SamAccountName: c.SamAccountName,
			Type:           c.Type,
			Score:          c.Score,
			Validation:     c.Validation,
			Severity:       extractSeverity(c.Reasons),
			Reasons:        c.Reasons,
			Evidence:       c.Evidence,
			Blockers:       c.Blockers,
			NextActions:    c.NextActions,
			SPNs:           c.SPNs,
		}
		data.Candidates = append(data.Candidates, candidate)

		// Count validation statuses
		if c.Validation != "" {
			data.ValidationCounts[c.Validation]++
		}
	}

	// Convert attack paths from graph
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
		}
	}

	return data
}

// htmlTemplate is the HTML template for the professional report
const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Cold Relay Security Assessment Report</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.5;
            color: #d4d4d4;
            background-color: #0d0d0d;
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
            border-bottom: 1px solid #262626;
        }

        .header h1 {
            font-size: 28px;
            font-weight: 600;
            color: #e5e5e5;
            margin-bottom: 6px;
            letter-spacing: -0.3px;
        }

        .header .subtitle {
            font-size: 12px;
            color: #737373;
            font-weight: 500;
            text-transform: uppercase;
            letter-spacing: 1px;
        }

        .header .meta {
            margin-top: 16px;
            font-size: 12px;
            color: #737373;
            display: flex;
            gap: 28px;
        }

        .header .meta span {
            display: flex;
            align-items: center;
            gap: 6px;
        }

        .header .meta strong {
            color: #d4d4d4;
            font-weight: 500;
        }

        .section {
            margin-bottom: 40px;
        }

        .section h2 {
            color: #e5e5e5;
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
            background: #171717;
            padding: 20px;
            border: 1px solid #262626;
        }

        .summary-card h3 {
            font-size: 11px;
            color: #737373;
            margin-bottom: 10px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            font-weight: 500;
        }

        .summary-card .value {
            font-size: 32px;
            font-weight: 600;
            color: #e5e5e5;
            letter-spacing: -0.8px;
        }

        .domain-info {
            background: #171717;
            padding: 20px;
            border: 1px solid #262626;
            margin-bottom: 20px;
        }

        .domain-info table {
            width: 100%;
            border-collapse: collapse;
        }

        .domain-info td {
            padding: 10px 0;
            border-bottom: 1px solid #262626;
            font-size: 13px;
        }

        .domain-info tr:last-child td {
            border-bottom: none;
        }

        .domain-info td:first-child {
            color: #737373;
            width: 180px;
            font-weight: 500;
        }

        .domain-info td:last-child {
            color: #d4d4d4;
            font-weight: 500;
        }

        .findings-table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 20px;
            font-size: 13px;
            background: #171717;
            border: 1px solid #262626;
        }

        .findings-table th,
        .findings-table td {
            padding: 12px 14px;
            text-align: left;
            border-bottom: 1px solid #262626;
        }

        .findings-table th {
            background-color: #1f1f1f;
            color: #a3a3a3;
            font-weight: 500;
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .findings-table td {
            color: #d4d4d4;
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
            color: #4ade80;
        }

        .badge-likely {
            color: #fbbf24;
        }

        .badge-theoretical {
            color: #a78bfa;
        }

        .badge-blocked {
            color: #f87171;
        }

        .badge-insufficient {
            color: #9ca3af;
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
            background: #171717;
            border: 1px solid #262626;
            padding: 20px;
            margin-bottom: 12px;
        }

        .attack-path h4 {
            color: #e5e5e5;
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
            color: #a3a3a3;
            font-size: 13px;
            padding-left: 16px;
            position: relative;
        }

        .evidence-list li:before,
        .blocker-list li:before {
            content: "•";
            position: absolute;
            left: 0;
            color: #525252;
        }

        .risk-insights {
            background: #171717;
            border: 1px solid #262626;
            padding: 20px;
        }

        .risk-insights h3 {
            color: #e5e5e5;
            margin-bottom: 12px;
            font-size: 14px;
            font-weight: 600;
        }

        .risk-insights ul {
            list-style: none;
        }

        .risk-insights li {
            margin-bottom: 8px;
            color: #d4d4d4;
            font-size: 13px;
            padding-left: 16px;
            position: relative;
        }

        .risk-insights li:before {
            content: "•";
            position: absolute;
            left: 0;
            color: #f87171;
        }

        .footer {
            margin-top: 48px;
            padding-top: 20px;
            border-top: 1px solid #262626;
            text-align: center;
            color: #737373;
            font-size: 12px;
        }

        .footer p {
            margin-bottom: 6px;
        }

        @media print {
            body {
                background-color: #fff;
                color: #171717;
            }
            .container {
                padding: 24px;
            }
            .header h1 {
                color: #171717;
            }
            .header .subtitle {
                color: #737373;
            }
            .header .meta strong {
                color: #171717;
            }
            .section h2 {
                color: #171717;
            }
            .summary-card,
            .domain-info,
            .attack-path,
            .risk-insights {
                background: #f5f5f5;
                border-color: #e5e5e5;
            }
            .summary-card .value,
            .domain-info td:last-child,
            .attack-path h4,
            .risk-insights h3,
            .risk-insights li {
                color: #171717;
            }
            .findings-table th {
                background-color: #e5e5e5;
                color: #525252;
            }
            .findings-table td {
                color: #404040;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Cold Relay</h1>
            <div class="subtitle">Security Assessment Report</div>
            <div class="meta">
                <span><strong>Domain:</strong> {{.Domain.Name}}</span>
                <span><strong>Generated:</strong> {{.GeneratedAt}}</span>
                <span><strong>Schema:</strong> {{.SchemaVersion}}</span>
            </div>
        </div>

        <!-- Executive Summary -->
        <div class="section">
            <h2>Executive Summary</h2>
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
        <div class="section">
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

        <!-- Detailed Findings -->
        <div class="section">
            <h2>Detailed Findings</h2>
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
                    {{range .Candidates}}
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
        </div>

        <!-- Attack Paths -->
        {{if .AttackPaths}}
        <div class="section">
            <h2>Attack Paths</h2>
            {{range .AttackPaths}}
            <div class="attack-path">
                <h4><span class="badge badge-{{.Validation | toLower}}">{{.Validation}}</span> <span class="badge severity-{{.Severity | toLower}}">{{.Severity}}</span> {{.Title}}</h4>
                {{if .Steps}}
                <strong>Attack Steps:</strong>
                <ul class="evidence-list">
                    {{range .Steps}}
                    <li>{{.}}</li>
                    {{end}}
                </ul>
                {{end}}
                {{if .Evidence}}
                <strong>Evidence:</strong>
                <ul class="evidence-list">
                    {{range .Evidence}}
                    <li>{{.}}</li>
                    {{end}}
                </ul>
                {{end}}
                {{if .Blockers}}
                <strong>Blockers:</strong>
                <ul class="blocker-list">
                    {{range .Blockers}}
                    <li>{{.}}</li>
                    {{end}}
                </ul>
                {{end}}
            </div>
            {{end}}
        </div>
        {{end}}

        <div class="footer">
            <p>Generated by Cold Relay v1.0.0 | For authorized security testing only</p>
            <p>This report contains sensitive security information. Handle with appropriate care.</p>
        </div>
    </div>
</body>
</html>
`
