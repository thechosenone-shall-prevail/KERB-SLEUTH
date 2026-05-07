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
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background-color: #f5f5f5;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: white;
            box-shadow: 0 0 20px rgba(0,0,0,0.1);
        }

        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            margin-bottom: 30px;
            border-radius: 8px;
        }

        .header h1 {
            font-size: 36px;
            margin-bottom: 10px;
        }

        .header .subtitle {
            font-size: 18px;
            opacity: 0.9;
        }

        .header .meta {
            margin-top: 20px;
            font-size: 14px;
            opacity: 0.8;
        }

        .section {
            margin-bottom: 40px;
        }

        .section h2 {
            color: #667eea;
            border-bottom: 3px solid #667eea;
            padding-bottom: 10px;
            margin-bottom: 20px;
            font-size: 24px;
        }

        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }

        .summary-card {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            border-left: 4px solid #667eea;
        }

        .summary-card h3 {
            font-size: 14px;
            color: #666;
            margin-bottom: 10px;
            text-transform: uppercase;
        }

        .summary-card .value {
            font-size: 32px;
            font-weight: bold;
            color: #333;
        }

        .domain-info {
            background: #e8f4f8;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 20px;
        }

        .domain-info table {
            width: 100%;
            border-collapse: collapse;
        }

        .domain-info td {
            padding: 10px;
            border-bottom: 1px solid #ddd;
        }

        .domain-info td:first-child {
            font-weight: bold;
            width: 200px;
        }

        .findings-table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 20px;
        }

        .findings-table th,
        .findings-table td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }

        .findings-table th {
            background-color: #667eea;
            color: white;
            font-weight: 600;
        }

        .findings-table tr:hover {
            background-color: #f5f5f5;
        }

        .badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
        }

        .badge-validated {
            background-color: #10b981;
            color: white;
        }

        .badge-likely {
            background-color: #f59e0b;
            color: white;
        }

        .badge-theoretical {
            background-color: #6366f1;
            color: white;
        }

        .badge-blocked {
            background-color: #ef4444;
            color: white;
        }

        .badge-insufficient {
            background-color: #6b7280;
            color: white;
        }

        .severity-critical {
            background-color: #dc2626;
            color: white;
        }

        .severity-high {
            background-color: #ea580c;
            color: white;
        }

        .severity-medium {
            background-color: #d97706;
            color: white;
        }

        .severity-low {
            background-color: #65a30d;
            color: white;
        }

        .attack-path {
            background: #fef3c7;
            border-left: 4px solid #f59e0b;
            padding: 20px;
            margin-bottom: 20px;
            border-radius: 4px;
        }

        .attack-path h4 {
            color: #92400e;
            margin-bottom: 10px;
        }

        .evidence-list,
        .blocker-list {
            margin-top: 10px;
        }

        .evidence-list li,
        .blocker-list li {
            margin-bottom: 5px;
        }

        .risk-insights {
            background: #fee2e2;
            border-left: 4px solid #ef4444;
            padding: 20px;
            border-radius: 4px;
        }

        .risk-insights h3 {
            color: #991b1b;
            margin-bottom: 15px;
        }

        .risk-insights ul {
            list-style-position: inside;
        }

        .risk-insights li {
            margin-bottom: 10px;
        }

        .footer {
            margin-top: 40px;
            padding-top: 20px;
            border-top: 2px solid #e5e7eb;
            text-align: center;
            color: #6b7280;
            font-size: 14px;
        }

        @media print {
            body {
                background-color: white;
            }
            .container {
                box-shadow: none;
                max-width: 100%;
            }
            .header {
                -webkit-print-color-adjust: exact;
                print-color-adjust: exact;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Cold Relay Security Assessment Report</h1>
            <div class="subtitle">Active Directory Security Assessment</div>
            <div class="meta">
                <p><strong>Domain:</strong> {{.Domain.Name}}</p>
                <p><strong>Generated:</strong> {{.GeneratedAt}}</p>
                <p><strong>Schema Version:</strong> {{.SchemaVersion}}</p>
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
