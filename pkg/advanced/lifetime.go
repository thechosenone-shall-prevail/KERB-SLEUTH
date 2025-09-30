package advanced

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// TicketLifetimeResult represents ticket lifetime analysis results
type TicketLifetimeResult struct {
	Username       string
	Domain         string
	StartTime      time.Time
	EndTime        time.Time
	RenewTill      time.Time
	Lifetime       time.Duration
	RenewalWindow  time.Duration
	Flags          []string
	EncryptionType int
	RiskScore      int
	RiskLevel      string
	Anomalies      []string
}

// TicketLifetimeAnalyzer handles ticket lifetime analysis
type TicketLifetimeAnalyzer struct {
	Results []*TicketLifetimeResult
}

// NewTicketLifetimeAnalyzer creates a new ticket lifetime analyzer
func NewTicketLifetimeAnalyzer() *TicketLifetimeAnalyzer {
	return &TicketLifetimeAnalyzer{
		Results: []*TicketLifetimeResult{},
	}
}

// AnalyzeTicketLifetime analyzes ticket lifetime patterns
func (tla *TicketLifetimeAnalyzer) AnalyzeTicketLifetime(ticketData map[string]interface{}) (*TicketLifetimeResult, error) {
	result := &TicketLifetimeResult{
		Username:       ticketData["username"].(string),
		Domain:         ticketData["domain"].(string),
		EncryptionType: 23,
		Flags:          []string{"FORWARDABLE", "RENEWABLE"},
		Anomalies:      []string{},
	}

	// Parse timestamps
	if startTime, ok := ticketData["start_time"].(string); ok {
		if t, err := time.Parse(time.RFC3339, startTime); err == nil {
			result.StartTime = t
		}
	}
	if endTime, ok := ticketData["end_time"].(string); ok {
		if t, err := time.Parse(time.RFC3339, endTime); err == nil {
			result.EndTime = t
		}
	}
	if renewTill, ok := ticketData["renew_till"].(string); ok {
		if t, err := time.Parse(time.RFC3339, renewTill); err == nil {
			result.RenewTill = t
		}
	}

	// Calculate durations
	result.Lifetime = result.EndTime.Sub(result.StartTime)
	result.RenewalWindow = result.RenewTill.Sub(result.StartTime)

	// Analyze for anomalies
	tla.analyzeAnomalies(result)

	// Calculate risk score
	result.RiskScore = tla.calculateRiskScore(result)
	result.RiskLevel = tla.determineRiskLevel(result.RiskScore)

	tla.Results = append(tla.Results, result)
	return result, nil
}

// GenerateTimeline generates a timeline visualization
func (tla *TicketLifetimeAnalyzer) GenerateTimeline() map[string]interface{} {
	timeline := make(map[string]interface{})

	var timelineData []map[string]interface{}
	for _, result := range tla.Results {
		timelineData = append(timelineData, map[string]interface{}{
			"username":   result.Username,
			"start_time": result.StartTime.Format(time.RFC3339),
			"end_time":   result.EndTime.Format(time.RFC3339),
			"lifetime":   result.Lifetime.String(),
			"risk_level": result.RiskLevel,
			"anomalies":  result.Anomalies,
		})
	}

	timeline["timeline_data"] = timelineData
	timeline["total_tickets"] = len(tla.Results)
	return timeline
}

// GenerateHeatmap generates a heatmap of ticket lifetimes
func (tla *TicketLifetimeAnalyzer) GenerateHeatmap() map[string]interface{} {
	heatmap := make(map[string]interface{})

	// Group by lifetime ranges
	ranges := map[string]int{
		"< 1 hour":   0,
		"1-8 hours":  0,
		"8-24 hours": 0,
		"1-7 days":   0,
		"> 7 days":   0,
	}

	for _, result := range tla.Results {
		lifetime := result.Lifetime
		if lifetime < time.Hour {
			ranges["< 1 hour"]++
		} else if lifetime < 8*time.Hour {
			ranges["1-8 hours"]++
		} else if lifetime < 24*time.Hour {
			ranges["8-24 hours"]++
		} else if lifetime < 7*24*time.Hour {
			ranges["1-7 days"]++
		} else {
			ranges["> 7 days"]++
		}
	}

	heatmap["lifetime_ranges"] = ranges
	heatmap["total_tickets"] = len(tla.Results)
	return heatmap
}

// ExportAnalysis exports analysis results
func (tla *TicketLifetimeAnalyzer) ExportAnalysis(outputDir string) error {
	// Export JSON
	jsonFile := fmt.Sprintf("%s/ticket_lifetime_analysis.json", outputDir)
	data, _ := json.MarshalIndent(tla.Results, "", "  ")
	os.WriteFile(jsonFile, data, 0644)

	// Export CSV
	csvFile := fmt.Sprintf("%s/ticket_lifetime_analysis.csv", outputDir)
	file, _ := os.Create(csvFile)
	defer file.Close()

	fmt.Fprintf(file, "Username,Domain,StartTime,EndTime,Lifetime,RiskLevel,Anomalies\n")
	for _, result := range tla.Results {
		fmt.Fprintf(file, "%s,%s,%s,%s,%s,%s,\"%s\"\n",
			result.Username, result.Domain,
			result.StartTime.Format(time.RFC3339),
			result.EndTime.Format(time.RFC3339),
			result.Lifetime.String(),
			result.RiskLevel,
			fmt.Sprintf("%v", result.Anomalies))
	}

	return nil
}

// Helper functions
func (tla *TicketLifetimeAnalyzer) analyzeAnomalies(result *TicketLifetimeResult) {
	if result.Lifetime > 24*time.Hour {
		result.Anomalies = append(result.Anomalies, "Unusually long ticket lifetime")
	}
	if result.Lifetime < 10*time.Minute {
		result.Anomalies = append(result.Anomalies, "Unusually short ticket lifetime")
	}
	if result.RenewalWindow > 7*24*time.Hour {
		result.Anomalies = append(result.Anomalies, "Excessive renewal window")
	}
}

func (tla *TicketLifetimeAnalyzer) calculateRiskScore(result *TicketLifetimeResult) int {
	score := 0
	score += len(result.Anomalies) * 25
	if result.Lifetime > 24*time.Hour {
		score += 30
	}
	if result.RenewalWindow > 7*24*time.Hour {
		score += 20
	}
	if score > 100 {
		score = 100
	}
	return score
}

func (tla *TicketLifetimeAnalyzer) determineRiskLevel(score int) string {
	if score >= 70 {
		return "High"
	} else if score >= 40 {
		return "Medium"
	}
	return "Low"
}
