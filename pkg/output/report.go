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
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            line-height: 1.6;
            color: #1a1a1a;
            background-color: #0a0a0a;
        }

        .container {
            max-width: 1000px;
            margin: 0 auto;
            padding: 60px 40px;
            background-color: #111;
        }

        .header {
            margin-bottom: 60px;
            padding-bottom: 30px;
            border-bottom: 1px solid #333;
        }

        .header h1 {
            font-size: 28px;
            font-weight: 700;
            color: #fff;
            margin-bottom: 8px;
            letter-spacing: -0.5px;
        }

        .header .subtitle {
            font-size: 14px;
            color: #666;
            font-weight: 500;
            text-transform: uppercase;
            letter-spacing: 1px;
        }

        .header .meta {
            margin-top: 24px;
            font-size: 13px;
            color: #888;
            display: flex;
            gap: 24px;
        }

        .header .meta p {
            display: flex;
            align-items: center;
            gap: 6px;
        }

        .header .meta strong {
            color: #fff;
        }

        .section {
            margin-bottom: 50px;
        }

        .section h2 {
            color: #fff;
            font-size: 18px;
            font-weight: 600;
            margin-bottom: 24px;
            letter-spacing: -0.3px;
        }

        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 16px;
            margin-bottom: 30px;
        }

        .summary-card {
            background: #1a1a1a;
            padding: 20px;
            border: 1px solid #333;
        }

        .summary-card h3 {
            font-size: 11px;
            color: #888;
            margin-bottom: 8px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            font-weight: 600;
        }

        .summary-card .value {
            font-size: 28px;
            font-weight: 700;
            color: #fff;
            letter-spacing: -1px;
        }

        .domain-info {
            background: #1a1a1a;
            padding: 20px;
            border: 1px solid #333;
            margin-bottom: 20px;
        }

        .domain-info table {
            width: 100%;
            border-collapse: collapse;
        }

        .domain-info td {
            padding: 12px 0;
            border-bottom: 1px solid #222;
            font-size: 13px;
        }

        .domain-info tr:last-child td {
            border-bottom: none;
        }

        .domain-info td:first-child {
            color: #888;
            width: 180px;
            font-weight: 500;
        }

        .domain-info td:last-child {
            color: #fff;
        }

        .findings-table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 20px;
            font-size: 13px;
        }

        .findings-table th,
        .findings-table td {
            padding: 14px 16px;
            text-align: left;
            border-bottom: 1px solid #333;
        }

        .findings-table th {
            background-color: #1a1a1a;
            color: #888;
            font-weight: 600;
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .findings-table td {
            color: #e0e0e0;
        }

        .findings-table tr:last-child td {
            border-bottom: none;
        }

        .badge {
            display: inline-block;
            padding: 4px 10px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.3px;
        }

        .badge-validated {
            background-color: #1a1a1a;
            color: #22c55e;
            border: 1px solid #22c55e;
        }

        .badge-likely {
            background-color: #1a1a1a;
            color: #f59e0b;
            border: 1px solid #f59e0b;
        }

        .badge-theoretical {
            background-color: #1a1a1a;
            color: #6366f1;
            border: 1px solid #6366f1;
        }

        .badge-blocked {
            background-color: #1a1a1a;
            color: #ef4444;
            border: 1px solid #ef4444;
        }

        .badge-insufficient {
            background-color: #1a1a1a;
            color: #6b7280;
            border: 1px solid #6b7280;
        }

        .severity-critical {
            background-color: #dc2626;
            color: white;
            border: none;
        }

        .severity-high {
            background-color: #ea580c;
            color: white;
            border: none;
        }

        .severity-medium {
            background-color: #d97706;
            color: white;
            border: none;
        }

        .severity-low {
            background-color: #65a30d;
            color: white;
            border: none;
        }

        .severity-unknown {
            background-color: #333;
            color: #888;
            border: none;
        }

        .attack-path {
            background: #1a1a1a;
            border: 1px solid #333;
            padding: 20px;
            margin-bottom: 16px;
        }

        .attack-path h4 {
            color: #fff;
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
            color: #999;
            font-size: 13px;
            padding-left: 16px;
            position: relative;
        }

        .evidence-list li:before,
        .blocker-list li:before {
            content: "•";
            position: absolute;
            left: 0;
            color: #666;
        }

        .risk-insights {
            background: #1a1a1a;
            border: 1px solid #333;
            padding: 20px;
        }

        .risk-insights h3 {
            color: #fff;
            margin-bottom: 16px;
            font-size: 14px;
            font-weight: 600;
        }

        .risk-insights ul {
            list-style: none;
        }

        .risk-insights li {
            margin-bottom: 8px;
            color: #e0e0e0;
            font-size: 13px;
            padding-left: 16px;
            position: relative;
        }

        .risk-insights li:before {
            content: "•";
            position: absolute;
            left: 0;
            color: #ef4444;
        }

        .footer {
            margin-top: 60px;
            padding-top: 30px;
            border-top: 1px solid #333;
            text-align: center;
            color: #666;
            font-size: 12px;
        }

        .footer p {
            margin-bottom: 8px;
        }

        @media print {
            body {
                background-color: #fff;
                color: #000;
            }
            .container {
                background-color: #fff;
                padding: 40px;
            }
            .header h1 {
                color: #000;
            }
            .header .subtitle {
                color: #666;
            }
            .header .meta strong {
                color: #000;
            }
            .section h2 {
                color: #000;
            }
            .summary-card,
            .domain-info,
            .attack-path,
            .risk-insights {
                background: #f5f5f5;
                border-color: #ddd;
            }
            .summary-card .value,
            .domain-info td:last-child,
            .attack-path h4,
            .risk-insights h3,
            .risk-insights li {
                color: #000;
            }
            .findings-table th {
                background-color: #f5f5f5;
                color: #666;
            }
            .findings-table td {
                color: #333;
            }
            .badge-validated,
            .badge-likely,
            .badge-theoretical,
            .badge-blocked,
            .badge-insufficient {
                background-color: #fff;
                border-color: #000;
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
                <p><strong>Domain:</strong> {{.Domain.Name}}</p>
                <p><strong>Generated:</strong> {{.GeneratedAt}}</p>
                <p><strong>Schema:</strong> {{.SchemaVersion}}</p>
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
