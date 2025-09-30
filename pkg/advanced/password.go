package advanced

import (
	"fmt"
	"log"
	"strings"
	"time"
)

// PasswordModificationResult represents password modification analysis results
type PasswordModificationResult struct {
	TargetAccount    string
	RequiredACLs     []string
	RequiredRights   []string
	ModificationPath []string
	RiskLevel        string
	Recommendations  []string
	DryRunMode       bool
}

// PasswordModificationAnalyzer handles password modification analysis
type PasswordModificationAnalyzer struct {
	AuditMode  bool
	DryRunMode bool
}

// NewPasswordModificationAnalyzer creates a new password modification analyzer
func NewPasswordModificationAnalyzer(auditMode, dryRunMode bool) *PasswordModificationAnalyzer {
	return &PasswordModificationAnalyzer{
		AuditMode:  auditMode,
		DryRunMode: dryRunMode,
	}
}

// AnalyzePasswordModification analyzes password modification requirements
func (pma *PasswordModificationAnalyzer) AnalyzePasswordModification(targetAccount string) (*PasswordModificationResult, error) {
	log.Printf("🔍 Analyzing password modification requirements for: %s", targetAccount)

	if !pma.AuditMode {
		return nil, fmt.Errorf("password modification analysis requires audit mode")
	}

	result := &PasswordModificationResult{
		TargetAccount:    targetAccount,
		RequiredACLs:     []string{},
		RequiredRights:   []string{},
		ModificationPath: []string{},
		Recommendations:  []string{},
		DryRunMode:       pma.DryRunMode,
	}

	// Analyze required ACLs
	pma.analyzeRequiredACLs(result)

	// Analyze required rights
	pma.analyzeRequiredRights(result)

	// Generate modification path
	pma.generateModificationPath(result)

	// Generate recommendations
	pma.generateRecommendations(result)

	// Determine risk level
	result.RiskLevel = pma.determineRiskLevel(result)

	return result, nil
}

// WhatWouldIChange provides interactive analysis mode
func (pma *PasswordModificationAnalyzer) WhatWouldIChange(targetAccount string) (map[string]interface{}, error) {
	log.Printf("🎯 Interactive analysis: What would I change for %s?", targetAccount)

	result, err := pma.AnalyzePasswordModification(targetAccount)
	if err != nil {
		return nil, err
	}

	analysis := map[string]interface{}{
		"target_account":     result.TargetAccount,
		"required_acls":      result.RequiredACLs,
		"required_rights":    result.RequiredRights,
		"modification_path":  result.ModificationPath,
		"risk_level":         result.RiskLevel,
		"recommendations":    result.Recommendations,
		"dry_run_mode":       result.DryRunMode,
		"analysis_timestamp": time.Now().Format(time.RFC3339),
	}

	return analysis, nil
}

// SimulatePasswordChange simulates password change process (audit mode only)
func (pma *PasswordModificationAnalyzer) SimulatePasswordChange(targetAccount, newPassword string) (*PasswordModificationResult, error) {
	if !pma.AuditMode {
		return nil, fmt.Errorf("password change simulation requires audit mode")
	}

	log.Printf("⚠️  SIMULATION: Password change for %s", targetAccount)

	result, err := pma.AnalyzePasswordModification(targetAccount)
	if err != nil {
		return nil, err
	}

	// Add simulation-specific information
	result.ModificationPath = append(result.ModificationPath, fmt.Sprintf("SIMULATION: Change password to: %s", newPassword))
	result.ModificationPath = append(result.ModificationPath, "SIMULATION: Update pwdLastSet timestamp")
	result.ModificationPath = append(result.ModificationPath, "SIMULATION: Log password change event")

	log.Printf("✅ Password change simulation completed for %s", targetAccount)
	return result, nil
}

// GeneratePasswordModificationReport generates a comprehensive report
func (pma *PasswordModificationAnalyzer) GeneratePasswordModificationReport(results []*PasswordModificationResult) map[string]interface{} {
	report := make(map[string]interface{})

	// Count by risk level
	riskCounts := make(map[string]int)
	for _, result := range results {
		riskCounts[result.RiskLevel]++
	}
	report["risk_distribution"] = riskCounts

	// High-risk modifications
	var highRisk []*PasswordModificationResult
	for _, result := range results {
		if result.RiskLevel == "High" {
			highRisk = append(highRisk, result)
		}
	}
	report["high_risk_modifications"] = highRisk

	// Required ACLs summary
	var allACLs []string
	for _, result := range results {
		allACLs = append(allACLs, result.RequiredACLs...)
	}
	report["required_acls"] = allACLs

	// Required rights summary
	var allRights []string
	for _, result := range results {
		allRights = append(allRights, result.RequiredRights...)
	}
	report["required_rights"] = allRights

	// Recommendations summary
	var allRecommendations []string
	for _, result := range results {
		allRecommendations = append(allRecommendations, result.Recommendations...)
	}
	report["recommendations"] = allRecommendations

	return report
}

// Helper functions

func (pma *PasswordModificationAnalyzer) analyzeRequiredACLs(result *PasswordModificationResult) {
	// Common ACLs required for password modification
	result.RequiredACLs = []string{
		"Reset Password",
		"Change Password",
		"Write Property (pwdLastSet)",
		"Write Property (userPassword)",
		"Write Property (unicodePwd)",
	}

	// Add account-specific ACLs
	if strings.Contains(strings.ToLower(result.TargetAccount), "admin") {
		result.RequiredACLs = append(result.RequiredACLs, "Domain Admin rights")
		result.RequiredACLs = append(result.RequiredACLs, "Account Operator rights")
	}
}

func (pma *PasswordModificationAnalyzer) analyzeRequiredRights(result *PasswordModificationResult) {
	// Common rights required for password modification
	result.RequiredRights = []string{
		"SeChangeNotifyPrivilege",
		"SeBackupPrivilege",
		"SeRestorePrivilege",
	}

	// Add account-specific rights
	if strings.Contains(strings.ToLower(result.TargetAccount), "service") {
		result.RequiredRights = append(result.RequiredRights, "Service Account modification rights")
	}
}

func (pma *PasswordModificationAnalyzer) generateModificationPath(result *PasswordModificationResult) {
	result.ModificationPath = []string{
		"1. Verify current permissions and ACLs",
		"2. Obtain necessary authentication credentials",
		"3. Connect to domain controller via LDAP/LDAPS",
		"4. Modify password attribute (unicodePwd)",
		"5. Update pwdLastSet timestamp",
		"6. Verify password change success",
		"7. Log password modification event",
	}

	if result.DryRunMode {
		result.ModificationPath = append(result.ModificationPath, "DRY RUN: No actual changes made")
	}
}

func (pma *PasswordModificationAnalyzer) generateRecommendations(result *PasswordModificationResult) {
	result.Recommendations = []string{
		"Always use secure LDAPS connections",
		"Implement proper audit logging",
		"Use least privilege principle",
		"Verify authorization before modification",
		"Test password changes in non-production environment first",
	}

	if result.RiskLevel == "High" {
		result.Recommendations = append(result.Recommendations, "URGENT: Review high-risk password modification")
		result.Recommendations = append(result.Recommendations, "Consider using alternative authentication methods")
	}

	if result.DryRunMode {
		result.Recommendations = append(result.Recommendations, "DRY RUN MODE: No actual modifications performed")
	}
}

func (pma *PasswordModificationAnalyzer) determineRiskLevel(result *PasswordModificationResult) string {
	score := 0

	// Base score for password modification
	score += 30

	// Add score for high-privilege accounts
	if strings.Contains(strings.ToLower(result.TargetAccount), "admin") {
		score += 40
	}

	// Add score for service accounts
	if strings.Contains(strings.ToLower(result.TargetAccount), "service") ||
		strings.Contains(strings.ToLower(result.TargetAccount), "svc") {
		score += 35
	}

	// Add score for number of required ACLs
	score += len(result.RequiredACLs) * 2

	// Dry run mode reduces risk
	if result.DryRunMode {
		score -= 20
	}

	// Cap at 100
	if score > 100 {
		score = 100
	}

	if score >= 70 {
		return "High"
	} else if score >= 40 {
		return "Medium"
	}
	return "Low"
}
