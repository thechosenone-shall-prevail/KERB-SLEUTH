package ai

import (
	"encoding/json"
	"fmt"
	"log"
	"math"
	"os"
	"time"

	"github.com/thechosenone-shall-prevail/KERB-SLEUTH/pkg/krb"
)

// RiskScore represents an AI-powered risk assessment
type RiskScore struct {
	OverallScore    float64                `json:"overall_score"`
	RiskLevel       string                 `json:"risk_level"`
	Confidence      float64                `json:"confidence"`
	Factors         []RiskFactor           `json:"factors"`
	Recommendations []string               `json:"recommendations"`
	Timestamp       time.Time              `json:"timestamp"`
	Metadata        map[string]interface{} `json:"metadata"`
}

// RiskFactor represents a specific risk factor
type RiskFactor struct {
	Name        string  `json:"name"`
	Score       float64 `json:"score"`
	Weight      float64 `json:"weight"`
	Description string  `json:"description"`
	Impact      string  `json:"impact"`
}

// AnomalyDetection represents anomaly detection results
type AnomalyDetection struct {
	Anomalies     []Anomaly          `json:"anomalies"`
	NormalPattern map[string]float64 `json:"normal_pattern"`
	Threshold     float64            `json:"threshold"`
	Confidence    float64            `json:"confidence"`
}

// Anomaly represents a detected anomaly
type Anomaly struct {
	Type        string                 `json:"type"`
	Severity    string                 `json:"severity"`
	Description string                 `json:"description"`
	Score       float64                `json:"score"`
	Timestamp   time.Time              `json:"timestamp"`
	Context     map[string]interface{} `json:"context"`
}

// AIRiskAnalyzer handles AI-powered risk analysis
type AIRiskAnalyzer struct {
	RiskWeights      map[string]float64
	AnomalyThreshold float64
	HistoricalData   []krb.Candidate
}

// NewAIRiskAnalyzer creates a new AI risk analyzer
func NewAIRiskAnalyzer() *AIRiskAnalyzer {
	return &AIRiskAnalyzer{
		RiskWeights: map[string]float64{
			"asrep_roasting":       0.3,
			"kerberoasting":        0.25,
			"rbcd_vulnerability":   0.2,
			"s4u_delegation":       0.15,
			"privilege_escalation": 0.1,
		},
		AnomalyThreshold: 0.7,
		HistoricalData:   []krb.Candidate{},
	}
}

// AnalyzeRisk performs AI-powered risk analysis
func (ara *AIRiskAnalyzer) AnalyzeRisk(candidates []krb.Candidate) (*RiskScore, error) {
	log.Printf("[*] Performing AI-powered risk analysis on %d candidates", len(candidates))

	// Calculate individual risk factors
	factors := []RiskFactor{
		ara.calculateASREPRisk(candidates),
		ara.calculateKerberoastingRisk(candidates),
		ara.calculateRBCDRisk(candidates),
		ara.calculateS4URisk(candidates),
		ara.calculatePrivilegeEscalationRisk(candidates),
	}

	// Calculate overall risk score
	overallScore := ara.calculateOverallScore(factors)
	riskLevel := ara.determineRiskLevel(overallScore)
	confidence := ara.calculateConfidence(factors)

	// Generate recommendations
	recommendations := ara.generateRecommendations(factors, overallScore)

	riskScore := &RiskScore{
		OverallScore:    overallScore,
		RiskLevel:       riskLevel,
		Confidence:      confidence,
		Factors:         factors,
		Recommendations: recommendations,
		Timestamp:       time.Now(),
		Metadata: map[string]interface{}{
			"total_candidates": len(candidates),
			"analysis_version": "1.0",
			"model_type":       "ensemble",
		},
	}

	log.Printf("[+] AI risk analysis completed: %s (%.2f)", riskLevel, overallScore)
	return riskScore, nil
}

// DetectAnomalies performs anomaly detection
func (ara *AIRiskAnalyzer) DetectAnomalies(candidates []krb.Candidate) (*AnomalyDetection, error) {
	log.Printf("[*] Performing anomaly detection on %d candidates", len(candidates))

	anomalies := []Anomaly{}

	// Detect unusual patterns
	anomalies = append(anomalies, ara.detectUnusualSPNs(candidates)...)
	anomalies = append(anomalies, ara.detectUnusualGroupMemberships(candidates)...)
	anomalies = append(anomalies, ara.detectUnusualAccountStates(candidates)...)
	anomalies = append(anomalies, ara.detectUnusualTimingPatterns(candidates)...)

	// Calculate normal patterns
	normalPattern := ara.calculateNormalPatterns(candidates)

	// Calculate confidence
	confidence := ara.calculateAnomalyConfidence(anomalies)

	detection := &AnomalyDetection{
		Anomalies:     anomalies,
		NormalPattern: normalPattern,
		Threshold:     ara.AnomalyThreshold,
		Confidence:    confidence,
	}

	log.Printf("[+] Anomaly detection completed: %d anomalies found", len(anomalies))
	return detection, nil
}

// Helper functions for risk analysis

func (ara *AIRiskAnalyzer) calculateASREPRisk(candidates []krb.Candidate) RiskFactor {
	asrepCount := 0
	for _, candidate := range candidates {
		if candidate.Type == "ASREP" {
			asrepCount++
		}
	}

	score := float64(asrepCount) / float64(len(candidates))
	if len(candidates) == 0 {
		score = 0
	}

	return RiskFactor{
		Name:        "AS-REP Roasting",
		Score:       score,
		Weight:      ara.RiskWeights["asrep_roasting"],
		Description: fmt.Sprintf("Found %d AS-REP roastable accounts", asrepCount),
		Impact:      "High - Pre-authentication disabled accounts",
	}
}

func (ara *AIRiskAnalyzer) calculateKerberoastingRisk(candidates []krb.Candidate) RiskFactor {
	kerberoastCount := 0
	for _, candidate := range candidates {
		if candidate.Type == "KERBEROAST" {
			kerberoastCount++
		}
	}

	score := float64(kerberoastCount) / float64(len(candidates))
	if len(candidates) == 0 {
		score = 0
	}

	return RiskFactor{
		Name:        "Kerberoasting",
		Score:       score,
		Weight:      ara.RiskWeights["kerberoasting"],
		Description: fmt.Sprintf("Found %d Kerberoastable accounts", kerberoastCount),
		Impact:      "High - Service account compromise",
	}
}

func (ara *AIRiskAnalyzer) calculateRBCDRisk(candidates []krb.Candidate) RiskFactor {
	// Simulate RBCD risk calculation
	rbcdRisk := 0.0
	for _, candidate := range candidates {
		// Check for suspicious group memberships that might indicate RBCD
		for _, group := range candidate.MemberOf {
			if contains([]string{"Domain Admins", "Enterprise Admins", "Schema Admins"}, group) {
				rbcdRisk += 0.3
			}
		}
	}

	score := math.Min(rbcdRisk, 1.0)

	return RiskFactor{
		Name:        "RBCD Vulnerability",
		Score:       score,
		Weight:      ara.RiskWeights["rbcd_vulnerability"],
		Description: "Potential Resource-Based Constrained Delegation vulnerabilities",
		Impact:      "Critical - Privilege escalation",
	}
}

func (ara *AIRiskAnalyzer) calculateS4URisk(candidates []krb.Candidate) RiskFactor {
	// Simulate S4U risk calculation
	s4uRisk := 0.0
	for _, candidate := range candidates {
		if len(candidate.SPNs) > 0 {
			s4uRisk += 0.2
		}
	}

	score := math.Min(s4uRisk, 1.0)

	return RiskFactor{
		Name:        "S4U Delegation",
		Score:       score,
		Weight:      ara.RiskWeights["s4u_delegation"],
		Description: "Potential S4U delegation vulnerabilities",
		Impact:      "High - Impersonation attacks",
	}
}

func (ara *AIRiskAnalyzer) calculatePrivilegeEscalationRisk(candidates []krb.Candidate) RiskFactor {
	// Simulate privilege escalation risk
	privEscRisk := 0.0
	for _, candidate := range candidates {
		for _, group := range candidate.MemberOf {
			if contains([]string{"Domain Admins", "Enterprise Admins"}, group) {
				privEscRisk += 0.5
			}
		}
	}

	score := math.Min(privEscRisk, 1.0)

	return RiskFactor{
		Name:        "Privilege Escalation",
		Score:       score,
		Weight:      ara.RiskWeights["privilege_escalation"],
		Description: "High-privilege accounts detected",
		Impact:      "Critical - Domain compromise",
	}
}

func (ara *AIRiskAnalyzer) calculateOverallScore(factors []RiskFactor) float64 {
	totalScore := 0.0
	totalWeight := 0.0

	for _, factor := range factors {
		totalScore += factor.Score * factor.Weight
		totalWeight += factor.Weight
	}

	if totalWeight == 0 {
		return 0.0
	}

	return totalScore / totalWeight
}

func (ara *AIRiskAnalyzer) determineRiskLevel(score float64) string {
	switch {
	case score >= 0.8:
		return "CRITICAL"
	case score >= 0.6:
		return "HIGH"
	case score >= 0.4:
		return "MEDIUM"
	case score >= 0.2:
		return "LOW"
	default:
		return "MINIMAL"
	}
}

func (ara *AIRiskAnalyzer) calculateConfidence(factors []RiskFactor) float64 {
	// Calculate confidence based on factor consistency
	if len(factors) == 0 {
		return 0.0
	}

	scores := make([]float64, len(factors))
	for i, factor := range factors {
		scores[i] = factor.Score
	}

	// Calculate standard deviation
	mean := 0.0
	for _, score := range scores {
		mean += score
	}
	mean /= float64(len(scores))

	variance := 0.0
	for _, score := range scores {
		variance += math.Pow(score-mean, 2)
	}
	variance /= float64(len(scores))

	stdDev := math.Sqrt(variance)

	// Lower standard deviation = higher confidence
	confidence := math.Max(0.0, 1.0-stdDev)
	return confidence
}

func (ara *AIRiskAnalyzer) generateRecommendations(factors []RiskFactor, overallScore float64) []string {
	recommendations := []string{}

	if overallScore >= 0.8 {
		recommendations = append(recommendations, "[!] IMMEDIATE ACTION REQUIRED: Critical vulnerabilities detected")
		recommendations = append(recommendations, "[!] Enable pre-authentication for all user accounts")
		recommendations = append(recommendations, "[!] Implement strong password policies")
		recommendations = append(recommendations, "[!] Enable comprehensive logging and monitoring")
	}

	if overallScore >= 0.6 {
		recommendations = append(recommendations, "[!] HIGH PRIORITY: Address high-risk vulnerabilities")
		recommendations = append(recommendations, "[!] Review and remediate Kerberoasting vulnerabilities")
		recommendations = append(recommendations, "[!] Implement additional security controls")
	}

	if overallScore >= 0.4 {
		recommendations = append(recommendations, "[!] MEDIUM PRIORITY: Review security posture")
		recommendations = append(recommendations, "[!] Conduct regular security assessments")
	}

	recommendations = append(recommendations, "[!] Provide security awareness training")
	recommendations = append(recommendations, "[!] Implement regular security monitoring")

	return recommendations
}

// Anomaly detection functions

func (ara *AIRiskAnalyzer) detectUnusualSPNs(candidates []krb.Candidate) []Anomaly {
	anomalies := []Anomaly{}

	// Count SPN patterns
	spnCounts := make(map[string]int)
	for _, candidate := range candidates {
		for _, spn := range candidate.SPNs {
			spnCounts[spn]++
		}
	}

	// Detect unusual SPN patterns
	for spn, count := range spnCounts {
		if count > 10 { // Threshold for unusual
			anomaly := Anomaly{
				Type:        "Unusual SPN Pattern",
				Severity:    "MEDIUM",
				Description: fmt.Sprintf("Unusual SPN pattern detected: %s (%d occurrences)", spn, count),
				Score:       0.7,
				Timestamp:   time.Now(),
				Context: map[string]interface{}{
					"spn":     spn,
					"count":   count,
					"pattern": "high_frequency",
				},
			}
			anomalies = append(anomalies, anomaly)
		}
	}

	return anomalies
}

func (ara *AIRiskAnalyzer) detectUnusualGroupMemberships(candidates []krb.Candidate) []Anomaly {
	anomalies := []Anomaly{}

	// Detect users with unusual group memberships
	for _, candidate := range candidates {
		adminGroups := 0
		for _, group := range candidate.MemberOf {
			if contains([]string{"Domain Admins", "Enterprise Admins", "Schema Admins"}, group) {
				adminGroups++
			}
		}

		if adminGroups > 2 {
			anomaly := Anomaly{
				Type:        "Unusual Group Membership",
				Severity:    "HIGH",
				Description: fmt.Sprintf("User %s has %d admin group memberships", candidate.SamAccountName, adminGroups),
				Score:       0.8,
				Timestamp:   time.Now(),
				Context: map[string]interface{}{
					"user":         candidate.SamAccountName,
					"admin_groups": adminGroups,
					"groups":       candidate.MemberOf,
				},
			}
			anomalies = append(anomalies, anomaly)
		}
	}

	return anomalies
}

func (ara *AIRiskAnalyzer) detectUnusualAccountStates(candidates []krb.Candidate) []Anomaly {
	anomalies := []Anomaly{}

	// Detect accounts with unusual characteristics
	for _, candidate := range candidates {
		// Check for accounts with many SPNs (potentially suspicious)
		if len(candidate.SPNs) > 5 {
			anomaly := Anomaly{
				Type:        "Account with Many SPNs",
				Severity:    "MEDIUM",
				Description: fmt.Sprintf("Account %s has %d SPNs", candidate.SamAccountName, len(candidate.SPNs)),
				Score:       0.6,
				Timestamp:   time.Now(),
				Context: map[string]interface{}{
					"user":      candidate.SamAccountName,
					"spns":      candidate.SPNs,
					"spn_count": len(candidate.SPNs),
				},
			}
			anomalies = append(anomalies, anomaly)
		}

		// Check for accounts with old passwords
		if time.Since(candidate.PwdLastSet) > 365*24*time.Hour {
			anomaly := Anomaly{
				Type:        "Account with Old Password",
				Severity:    "LOW",
				Description: fmt.Sprintf("Account %s has password older than 1 year", candidate.SamAccountName),
				Score:       0.4,
				Timestamp:   time.Now(),
				Context: map[string]interface{}{
					"user":         candidate.SamAccountName,
					"pwd_last_set": candidate.PwdLastSet,
					"age_days":     int(time.Since(candidate.PwdLastSet).Hours() / 24),
				},
			}
			anomalies = append(anomalies, anomaly)
		}
	}

	return anomalies
}

func (ara *AIRiskAnalyzer) detectUnusualTimingPatterns(candidates []krb.Candidate) []Anomaly {
	anomalies := []Anomaly{}

	// Simulate timing pattern detection
	// In real implementation, this would analyze login times, etc.

	return anomalies
}

func (ara *AIRiskAnalyzer) calculateNormalPatterns(candidates []krb.Candidate) map[string]float64 {
	patterns := make(map[string]float64)

	// Calculate normal patterns
	totalUsers := len(candidates)
	if totalUsers == 0 {
		return patterns
	}

	// Calculate percentage of users with SPNs
	usersWithSPNs := 0
	for _, candidate := range candidates {
		if len(candidate.SPNs) > 0 {
			usersWithSPNs++
		}
	}
	patterns["users_with_spns"] = float64(usersWithSPNs) / float64(totalUsers)

	// Calculate percentage of admin users
	adminUsers := 0
	for _, candidate := range candidates {
		for _, group := range candidate.MemberOf {
			if contains([]string{"Domain Admins", "Enterprise Admins"}, group) {
				adminUsers++
				break
			}
		}
	}
	patterns["admin_users"] = float64(adminUsers) / float64(totalUsers)

	return patterns
}

func (ara *AIRiskAnalyzer) calculateAnomalyConfidence(anomalies []Anomaly) float64 {
	if len(anomalies) == 0 {
		return 1.0
	}

	// Calculate confidence based on anomaly severity distribution
	highSeverity := 0
	mediumSeverity := 0
	lowSeverity := 0

	for _, anomaly := range anomalies {
		switch anomaly.Severity {
		case "HIGH":
			highSeverity++
		case "MEDIUM":
			mediumSeverity++
		case "LOW":
			lowSeverity++
		}
	}

	// Higher confidence with more high-severity anomalies
	totalAnomalies := len(anomalies)
	confidence := float64(highSeverity*3+mediumSeverity*2+lowSeverity) / float64(totalAnomalies*3)

	return math.Min(confidence, 1.0)
}

// Utility functions

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// ExportRiskAnalysis exports risk analysis to JSON
func (ara *AIRiskAnalyzer) ExportRiskAnalysis(riskScore *RiskScore, outputFile string) error {
	log.Printf("[*] Exporting AI risk analysis to: %s", outputFile)

	data, err := json.MarshalIndent(riskScore, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal risk analysis: %v", err)
	}

	err = os.WriteFile(outputFile, data, 0644)
	if err != nil {
		return fmt.Errorf("failed to write risk analysis file: %v", err)
	}

	log.Printf("[+] AI risk analysis exported successfully")
	return nil
}

// ExportAnomalyDetection exports anomaly detection to JSON
func (ara *AIRiskAnalyzer) ExportAnomalyDetection(detection *AnomalyDetection, outputFile string) error {
	log.Printf("[*] Exporting anomaly detection to: %s", outputFile)

	data, err := json.MarshalIndent(detection, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal anomaly detection: %v", err)
	}

	err = os.WriteFile(outputFile, data, 0644)
	if err != nil {
		return fmt.Errorf("failed to write anomaly detection file: %v", err)
	}

	log.Printf("[+] Anomaly detection exported successfully")
	return nil
}
