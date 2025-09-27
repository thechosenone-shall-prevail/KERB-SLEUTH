package triage

import (
	"strings"
	"time"

	"github.com/thechosenone-shall-prevail/kerb-sleuth/pkg/krb"
)

type Config struct {
	Weights     Weights    `yaml:"weights"`
	Thresholds  Thresholds `yaml:"thresholds"`
	Time        TimeConfig `yaml:"time"`
	AdminGroups []string   `yaml:"admin_groups"`
}

type Weights struct {
	ASREPBase            int `yaml:"asrep_base"`
	ASREPPreauth         int `yaml:"asrep_preauth"`
	ASREPPwdOld          int `yaml:"asrep_pwd_old"`
	ASREPAdminGroup      int `yaml:"asrep_admin_group"`
	ASREPDisabledPenalty int `yaml:"asrep_disabled_penalty"`
	KerberoastBase       int `yaml:"kerberoast_base"`
	KerberoastSPN        int `yaml:"kerberoast_spn"`
	KerberoastPwdOld     int `yaml:"kerberoast_pwd_old"`
}

type Thresholds struct {
	High   int `yaml:"high"`
	Medium int `yaml:"medium"`
}

type TimeConfig struct {
	PwdOldDays int `yaml:"pwd_old_days"`
}

func DefaultConfig() *Config {
	return &Config{
		Weights: Weights{
			ASREPBase:            50,
			ASREPPreauth:         20,
			ASREPPwdOld:          15,
			ASREPAdminGroup:      10,
			ASREPDisabledPenalty: -20,
			KerberoastBase:       40,
			KerberoastSPN:        20,
			KerberoastPwdOld:     15,
		},
		Thresholds: Thresholds{
			High:   80,
			Medium: 50,
		},
		Time: TimeConfig{
			PwdOldDays: 90,
		},
		AdminGroups: []string{
			"CN=Domain Admins",
			"CN=Enterprise Admins",
			"CN=Schema Admins",
			"Administrators",
			"Backup Operators",
		},
	}
}

func ScoreCandidates(asreps, kerb []krb.Candidate, cfg *Config) []krb.Candidate {
	var scored []krb.Candidate

	// Score AS-REP candidates
	for _, candidate := range asreps {
		candidate.Score = cfg.Weights.ASREPBase

		// Add preauth weight
		candidate.Score += cfg.Weights.ASREPPreauth

		// Check password age
		if !candidate.PwdLastSet.IsZero() &&
			time.Since(candidate.PwdLastSet).Hours() > float64(cfg.Time.PwdOldDays*24) {
			candidate.Score += cfg.Weights.ASREPPwdOld
		}

		// Check admin group membership
		if isInAdminGroup(candidate.MemberOf, cfg.AdminGroups) {
			candidate.Score += cfg.Weights.ASREPAdminGroup
		}

		// Add severity to reasons
		severity := getSeverity(candidate.Score, cfg.Thresholds)
		candidate.Reasons = append(candidate.Reasons, severity)

		scored = append(scored, candidate)
	}

	// Score Kerberoast candidates
	for _, candidate := range kerb {
		candidate.Score = cfg.Weights.KerberoastBase

		// Add SPN weight
		if len(candidate.SPNs) > 0 {
			candidate.Score += cfg.Weights.KerberoastSPN
		}

		// Check password age
		if !candidate.PwdLastSet.IsZero() &&
			time.Since(candidate.PwdLastSet).Hours() > float64(cfg.Time.PwdOldDays*24) {
			candidate.Score += cfg.Weights.KerberoastPwdOld
		}

		// Check admin group membership
		if isInAdminGroup(candidate.MemberOf, cfg.AdminGroups) {
			candidate.Score += cfg.Weights.ASREPAdminGroup
		}

		// Add severity to reasons
		severity := getSeverity(candidate.Score, cfg.Thresholds)
		candidate.Reasons = append(candidate.Reasons, severity)

		scored = append(scored, candidate)
	}

	return scored
}

func isInAdminGroup(userGroups, adminGroups []string) bool {
	for _, userGroup := range userGroups {
		userGroupLower := strings.ToLower(userGroup)
		for _, adminGroup := range adminGroups {
			adminGroupLower := strings.ToLower(adminGroup)
			if strings.Contains(userGroupLower, adminGroupLower) {
				return true
			}
		}
	}
	return false
}

func getSeverity(score int, thresholds Thresholds) string {
	if score >= thresholds.High {
		return "Severity: High"
	} else if score >= thresholds.Medium {
		return "Severity: Medium"
	}
	return "Severity: Low"
}
