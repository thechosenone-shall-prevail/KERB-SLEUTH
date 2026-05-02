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

	"github.com/thechosenone-shall-prevail/KERB-SLEUTH/pkg/advanced"
	"github.com/thechosenone-shall-prevail/KERB-SLEUTH/pkg/cracker"
	"github.com/thechosenone-shall-prevail/KERB-SLEUTH/pkg/ingest"
	"github.com/thechosenone-shall-prevail/KERB-SLEUTH/pkg/kerberos"
	"github.com/thechosenone-shall-prevail/KERB-SLEUTH/pkg/krb"
	"github.com/thechosenone-shall-prevail/KERB-SLEUTH/pkg/output"
	"github.com/thechosenone-shall-prevail/KERB-SLEUTH/pkg/triage"
	"github.com/thechosenone-shall-prevail/KERB-SLEUTH/pkg/util"
	"gopkg.in/yaml.v3"
)

const version = "2.1.0"

func main() {
	// ── flags ────────────────────────────────────────────────────────────
	// Auth
	user := flag.String("u", "", "Username  (DOMAIN\\user  or  user@domain)")
	pass := flag.String("p", "", "Password")
	domain := flag.String("d", "", "Domain  (auto-detected from target if omitted)")

	// Connection
	ssl := flag.Bool("ssl", false, "Force LDAPS (port 636)")
	startTLS := flag.Bool("starttls", false, "Upgrade LDAP 389 → TLS")
	insecure := flag.Bool("k", false, "Skip TLS cert verification")
	timeout := flag.Duration("timeout", 10*time.Second, "Connection timeout")

	// Output
	outFile := flag.String("o", "results.json", "Output file")
	csvOut := flag.Bool("csv", false, "Also write CSV")
	siem := flag.Bool("siem", false, "Also write Sigma rules")
	jsonOnly := flag.Bool("json", false, "Print JSON to stdout (no file)")

	// Offline file analysis
	file := flag.String("f", "", "Offline AD export file  (CSV / JSON / LDIF)")

	// Attacks
	crack := flag.Bool("crack", false, "Extract hashes + invoke hashcat/john")
	wordlist := flag.String("w", "/usr/share/wordlists/rockyou.txt", "Wordlist for cracking")
	realKerb := flag.Bool("real", false, "Use real Kerberos protocol  (AS-REQ / TGS-REQ)")

	// Advanced
	adv := flag.Bool("A", false, "Run ALL advanced modules  (RBCD, S4U, DCSync …)")
	audit := flag.Bool("audit", false, "Audit mode  (read-only, no exploitation)")
	rbcd := flag.Bool("rbcd", false, "RBCD enumeration")
	s4u := flag.Bool("s4u", false, "S4U delegation analysis")
	dcsync := flag.Bool("dcsync", false, "DCSync rights enumeration")
	pkinit := flag.Bool("pkinit", false, "PKINIT / AD CS analysis")

	// Safety
	authorized := flag.Bool("yes", false, "Confirm you are authorized  (required for --crack / --real)")

	// Config
	configFile := flag.String("config", "configs/defaults.yml", "Config file")

	// ── parse ────────────────────────────────────────────────────────────
	flag.Usage = printUsage
	
	// Smart Argument Reordering:
	reorderedArgs := []string{os.Args[0]}
	var targetCandidate string
	skipNext := false
	
	valFlags := map[string]bool{
		"u": true, "p": true, "d": true, "o": true, "f": true, "w": true, "timeout": true, "config": true,
	}

	for i := 1; i < len(os.Args); i++ {
		arg := os.Args[i]
		if skipNext {
			reorderedArgs = append(reorderedArgs, arg)
			skipNext = false
			continue
		}

		if strings.HasPrefix(arg, "-") {
			reorderedArgs = append(reorderedArgs, arg)
			name := strings.TrimLeft(strings.Split(arg, "=")[0], "-")
			if valFlags[name] && !strings.Contains(arg, "=") {
				skipNext = true
			}
		} else if targetCandidate == "" {
			targetCandidate = arg
		} else {
			reorderedArgs = append(reorderedArgs, arg)
		}
	}

	if targetCandidate != "" {
		reorderedArgs = append(reorderedArgs, targetCandidate)
	}
	
	os.Args = reorderedArgs
	flag.Parse()

	target := flag.Arg(0) 

	// ── route ────────────────────────────────────────────────────────────
	if target == "help" || target == "--help" || target == "-h" {
		printUsage()
		os.Exit(0)
	}
	if target == "version" || target == "--version" || target == "-v" {
		fmt.Printf("kerb-sleuth v%s\n", version)
		os.Exit(0)
	}

	util.DisplayBanner(version)

	if *file != "" {
		runOfflineAnalysis(*file, *outFile, *csvOut, *siem, *jsonOnly, *configFile)
		return
	}

	if target == "" {
		printUsage()
		os.Exit(1)
	}

	// ── protocol discovery ───────────────────────────────────────────────
	runProtocolDiscovery(target)

	// ── build credentials string ─────────────────────────────────────────
	bindUser := *user
	if *domain != "" && bindUser != "" && !strings.Contains(bindUser, "\\") && !strings.Contains(bindUser, "@") {
		bindUser = *domain + "\\" + bindUser
	}

	// ── connect ──────────────────────────────────────────────────────────
	connOpts := krb.ConnectOptions{
		Target:   target,
		BindUser: bindUser,
		BindPass: *pass,
		UseSSL:   *ssl,
		StartTLS: *startTLS,
		Insecure: *insecure,
		Timeout:  *timeout,
	}

	client, err := smartConnect(connOpts)
	if err != nil {
		log.Fatalf("[x] %v", err)
	}
	defer client.Close()

	// ── enumerate ────────────────────────────────────────────────────────
	users, err := client.EnumerateUsers()
	if err != nil {
		log.Fatalf("[x] User enumeration failed: %v", err)
	}
	log.Printf("[+] %d users found", len(users))

	domainInfo, _ := client.GetDomainInfo()

	// ── analyse ──────────────────────────────────────────────────────────
	cfg := loadConfigSafe(*configFile)

	asrep := krb.FindASREPCandidates(users)
	kerb := krb.FindKerberoastCandidates(users)
	all := triage.ScoreCandidates(asrep, kerb, cfg)

	log.Printf("[+] %d AS-REP roastable  |  %d Kerberoastable", len(asrep), len(kerb))

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
		runRealKerberos(target, bindUser, *pass)
	}

	// ── advanced modules ─────────────────────────────────────────────────
	var advResults map[string]interface{}
	if *adv || *rbcd || *s4u || *dcsync || *pkinit {
		advResults = runAdvanced(client, cfg, *adv, *audit, *rbcd, *s4u, *dcsync, *pkinit, target, bindUser, *pass, *domain)
		
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
		}
	}
	results.Summary.HighRiskObjects = results.Summary.ASREPCandidates + results.Summary.KerberoastCandidates + results.Summary.ReconCandidates + results.Summary.HVTCandidates

	if len(results.RiskInsights) > 0 {
		log.Printf("[!] Attack Path Insights Detected:")
		for _, insight := range results.RiskInsights {
			color := util.Yellow
			if strings.Contains(insight, "[CRITICAL]") || strings.Contains(insight, "[HIGH]") {
				color = util.Red
			} else if strings.HasPrefix(insight, "---") || strings.HasPrefix(insight, "→") {
				color = util.Cyan
			}
			log.Printf("    %s%s%s", color, insight, util.Reset)
		}
	}

	// ── output ───────────────────────────────────────────────────────────
	writeResults(results, all, cfg, *outFile, *csvOut, *siem, *jsonOnly)

	log.Printf("[+] Results → %s", *outFile)
	log.Printf("[+] Done: %d candidates (%d Kerberos / %d Recon / %d HVT)", 
		results.Summary.HighRiskObjects,
		results.Summary.ASREPCandidates+results.Summary.KerberoastCandidates,
		results.Summary.ReconCandidates,
		results.Summary.HVTCandidates)
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
		
		// Search Description for passwords
		patterns := []string{"password", "pass:", "pwd=", "secret", "creds"}
		desc := strings.ToLower(u.Description)
		for _, p := range patterns {
			if strings.Contains(desc, p) {
				insights = append(insights, fmt.Sprintf("[HIGH] Potential credential in Description: %s (Found keyword: '%s')", u.SamAccountName, p))
				candidates = append(candidates, krb.Candidate{
					SamAccountName: u.SamAccountName,
					Type:           "RECON",
					Score:          80,
					Reasons:        []string{fmt.Sprintf("Potential credential in Description (Keyword: %s)", p)},
				})
				break
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
			for _, f := range files {
				sharesFound[f.Share]++
			}
			for s, count := range sharesFound {
				insights = append(insights, fmt.Sprintf("[HIGH] READ access to juicy share: %s (Found %d sensitive files)", s, count))
				candidates = append(candidates, krb.Candidate{
					SamAccountName: s,
					Type:           "RECON",
					Score:          85,
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
	
	protocols := []struct {
		name  string
		port  int
		color string
	}{
		{"LDAP", 389, util.Cyan},
		{"SMB", 445, util.Green},
		{"WinRM", 5985, util.Yellow},
		{"RDP", 3389, util.Magenta},
		{"RPC", 135, util.Blue},
	}

	hits := []string{}
	for _, p := range protocols {
		addr := fmt.Sprintf("%s:%d", target, p.port)
		conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err == nil {
			conn.Close()
			hits = append(hits, fmt.Sprintf("%s%s:%d%s", p.color, p.name, p.port, util.Reset))
		}
	}

	if len(hits) > 0 {
		log.Printf("[+] Services detected: %s", strings.Join(hits, " | "))
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// ADVANCED MODULES
// ═══════════════════════════════════════════════════════════════════════════

func printUsage() {
	h := util.Green
	r := util.Reset
	g := util.DarkGray

	fmt.Printf("KERB-SLEUTH v%s — Kerberos Security Scanner\n\n", version)

	fmt.Println("USAGE:")
	fmt.Printf("  %skerb-sleuth <target>%s                            anonymous scan\n", h, r)
	fmt.Printf("  %skerb-sleuth <target> -u <user> -p <pass>%s        authenticated\n", h, r)
	fmt.Printf("  %skerb-sleuth <target> -u <user> -p <pass> --ssl%s  LDAPS\n", h, r)
	fmt.Printf("  %skerb-sleuth -f users.csv%s                        offline analysis\n", h, r)
	fmt.Println()

	fmt.Println("EXAMPLES:")
	fmt.Printf("  %s# Quick scan (auto-detects LDAP/LDAPS)%s\n", g, r)
	fmt.Printf("  %skerb-sleuth 10.10.10.100%s\n", h, r)
	fmt.Println()
	fmt.Printf("  %s# Authenticated + LDAPS%s\n", g, r)
	fmt.Printf("  %skerb-sleuth dc01.corp.local -u admin -p P@ss -d CORP --ssl -k%s\n", h, r)
	fmt.Println()
	fmt.Printf("  %s# Extract hashes + crack%s\n", g, r)
	fmt.Printf("  %skerb-sleuth 10.10.10.100 -u user -p pass --crack --yes%s\n", h, r)
	fmt.Println()
	fmt.Printf("  %s# Advanced modules%s\n", g, r)
	fmt.Printf("  %skerb-sleuth 10.10.10.100 -u user -p pass -A --audit%s\n", h, r)
	fmt.Println()

	fmt.Println("FLAGS:")
	fmt.Println("  Target & Auth:")
	fmt.Println("    <target>              DC address  (IP or hostname, first arg)")
	fmt.Println("    -u  <user>            Username")
	fmt.Println("    -p  <pass>            Password")
	fmt.Println("    -d  <domain>          Domain  (auto-detected if omitted)")
	fmt.Println()
	fmt.Println("  Connection:")
	fmt.Println("    --ssl                 Force LDAPS  (port 636)")
	fmt.Println("    --starttls            Upgrade 389 → TLS")
	fmt.Println("    -k                    Skip TLS cert verify")
	fmt.Println("    --timeout <dur>       Connection timeout  (default 10s)")
	fmt.Println()
	fmt.Println("  Output:")
	fmt.Println("    -o  <file>            Output file")
	fmt.Println("    --csv                 Also write CSV")
	fmt.Println("    --siem                Also write Sigma rules")
	fmt.Println("    --json                Print JSON to stdout")
	fmt.Println()
	fmt.Println("  Attacks:")
	fmt.Println("    --crack               Extract hashes + crack  (needs --yes)")
	fmt.Println("    -w  <wordlist>        Wordlist")
	fmt.Println("    --real                Real Kerberos  AS-REQ/TGS-REQ")
	fmt.Println()
	fmt.Println("  Advanced:")
	fmt.Println("    -A                    Run ALL advanced modules")
	fmt.Println("    --audit               Audit mode  (read-only)")
	fmt.Println()
	fmt.Printf("  %sWARNING: Only use on systems you own or have written permission to test.%s\n", util.Red, r)
}

func smartConnect(opts krb.ConnectOptions) (*krb.LDAPClient, error) {
	if opts.UseSSL || opts.StartTLS {
		return krb.Connect(opts)
	}

	log.Printf("[*] Auto-detecting connection to %s …", opts.Target)

	client, err := krb.Connect(opts)
	if err == nil {
		return client, nil
	}

	log.Printf("[!] LDAP failed (%v), trying LDAPS …", err)
	opts.UseSSL = true
	opts.Insecure = true 
	client, err = krb.Connect(opts)
	if err == nil {
		return client, nil
	}

	return nil, fmt.Errorf("could not connect to %s via LDAP or LDAPS.\n"+
		"    Try: kerb-sleuth %s -u <user> -p <pass> --ssl -k\n"+
		"    Error: %v", opts.Target, opts.Target, err)
}

func runOfflineAnalysis(filePath, outFile string, csvOut, siemOut, jsonOnly bool, configPath string) {
	log.Printf("[*] Parsing %s …", filePath)

	users, err := ingest.ParseAD(filePath)
	if err != nil {
		log.Fatalf("[x] Failed to parse file: %v", err)
	}
	log.Printf("[+] %d users loaded", len(users))

	cfg := loadConfigSafe(configPath)

	asrep := krb.FindASREPCandidates(users)
	kerb := krb.FindKerberoastCandidates(users)
	all := triage.ScoreCandidates(asrep, kerb, cfg)

	if outFile == "" {
		base := strings.TrimSuffix(filepath.Base(filePath), filepath.Ext(filePath))
		outFile = base + "_results.json"
	}

	results := output.Results{
		Summary: output.Summary{
			TotalUsers:           len(users),
			ASREPCandidates:      len(asrep),
			KerberoastCandidates: len(kerb),
		},
		Candidates: all,
		Users:      users,
	}

	writeResults(results, all, cfg, outFile, csvOut, siemOut, jsonOnly)
}

func extractAndCrack(candidates []krb.Candidate, wordlistPath string, client *krb.LDAPClient) {
	if len(candidates) == 0 {
		log.Printf("[!] No candidates to extract hashes from")
		return
	}

	domainInfo, err := client.GetDomainInfo()
	if err != nil {
		log.Printf("[x] Could not get domain info: %v", err)
		return
	}

	hashDir := "hashes"
	os.MkdirAll(hashDir, 0755)

	var asrepHashes, kerbHashes []string

	for _, c := range candidates {
		switch c.Type {
		case "ASREP":
			h, err := client.ExtractASREPHash(c.SamAccountName, domainInfo.DomainName)
			if err != nil {
				continue
			}
			asrepHashes = append(asrepHashes, h.Hash)
		case "KERBEROAST":
			for _, spn := range c.SPNs {
				h, err := client.ExtractKerberoastHash(c.SamAccountName, domainInfo.DomainName, spn)
				if err != nil {
					continue
				}
				kerbHashes = append(kerbHashes, h.Hash)
			}
		}
	}

	if len(asrepHashes) > 0 {
		f := filepath.Join(hashDir, "asrep.txt")
		writeHashes(f, asrepHashes)
		crackAndShow("asrep", f, wordlistPath)
	}
	if len(kerbHashes) > 0 {
		f := filepath.Join(hashDir, "kerberoast.txt")
		writeHashes(f, kerbHashes)
		crackAndShow("kerberoast", f, wordlistPath)
	}
}

func writeHashes(path string, hashes []string) {
	f, _ := os.Create(path)
	defer f.Close()
	for _, h := range hashes {
		fmt.Fprintln(f, h)
	}
}

func crackAndShow(attackType, hashFile, wordlist string) {
	results, _ := cracker.CrackHashes(hashFile, wordlist, attackType)
	for hash, pw := range results {
		log.Printf("[+] CRACKED: %s… → %s", hash[:10], pw)
	}
}

func runRealKerberos(target, user, pass string) {
	kc, _ := kerberos.NewKerberosClient(target, target)
	if user != "" && pass != "" {
		kc.AuthenticateWithPassword(user, pass)
	}
}

func runAdvanced(client *krb.LDAPClient, cfg *triage.Config, all, auditMode, rbcd, s4u, dcsync, pkinit bool, target, user, pass, domain string) map[string]interface{} {
	log.Printf("[*] Running advanced analysis …")

	a := advanced.NewAdvancedAnalyzer(client, auditMode, false, target, user, pass, domain)

	if all {
		a.RunFullAnalysis()
		return a.Results
	}

	if rbcd { a.RunRBCDAnalysis() }
	if s4u { a.RunS4UAnalysis() }
	if dcsync { a.RunDCSyncAnalysis() }
	if pkinit { a.RunPKINITAnalysis() }

	return a.Results
}

func writeResults(results output.Results, candidates []krb.Candidate, cfg *triage.Config, outFile string, csvOut, siemOut, jsonOnly bool) {
	hi, med, lo := 0, 0, 0
	for _, c := range candidates {
		switch {
		case c.Score >= cfg.Thresholds.High: hi++
		case c.Score >= cfg.Thresholds.Medium: med++
		default: lo++
		}
	}

	if jsonOnly {
		data, _ := json.MarshalIndent(results, "", "  ")
		fmt.Println(string(data))
	} else {
		output.WriteJSON(outFile, results)
		log.Printf("[+] Results → %s", outFile)
	}

	if csvOut {
		output.WriteCSV(strings.TrimSuffix(outFile, ".json")+".csv", results)
	}

	log.Printf("[+] Done: %d candidates  (%s%d high%s / %d med / %d low)",
		len(candidates), util.Red, hi, util.Reset, med, lo)
}

func loadConfigSafe(path string) *triage.Config {
	data, err := os.ReadFile(path)
	if err != nil { return triage.DefaultConfig() }
	var cfg triage.Config
	yaml.Unmarshal(data, &cfg)
	return &cfg
}
