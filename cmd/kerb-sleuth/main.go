package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
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

const version = "2.0.0"

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
	outFile := flag.String("o", "", "Output file  (default: <target>_results.json)")
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
	// Go's flag package stops at the first non-flag argument. To support:
	// 'kerb-sleuth 10.10.10.100 -A' we need to move the target to the end.
	reorderedArgs := []string{os.Args[0]}
	var targetCandidate string
	skipNext := false
	
	// Flags that take values (must be synced with flag definitions)
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
			// Check if this flag takes a value and doesn't use '='
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

	target := flag.Arg(0) // Target is now guaranteed to be the first positional arg after flags

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

	// Offline file analysis  →  kerb-sleuth -f users.csv
	if *file != "" {
		runOfflineAnalysis(*file, *outFile, *csvOut, *siem, *jsonOnly, *configFile)
		return
	}

	// No target, no file → show help
	if target == "" {
		printUsage()
		os.Exit(1)
	}

	// ── build credentials string ─────────────────────────────────────────
	bindUser := *user
	if *domain != "" && bindUser != "" && !strings.Contains(bindUser, "\\") && !strings.Contains(bindUser, "@") {
		bindUser = *domain + "\\" + bindUser
	}

	// ── auto-detect output file name ─────────────────────────────────────
	if *outFile == "" {
		safeTarget := strings.ReplaceAll(strings.ReplaceAll(target, ".", "_"), ":", "_")
		*outFile = safeTarget + "_results.json"
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

	// Smart connection: if no --ssl / --starttls, try LDAP first then LDAPS
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

	// ── analyse ──────────────────────────────────────────────────────────
	cfg := loadConfigSafe(*configFile)

	asrep := krb.FindASREPCandidates(users)
	kerb := krb.FindKerberoastCandidates(users)
	all := triage.ScoreCandidates(asrep, kerb, cfg)

	log.Printf("[+] %d AS-REP roastable  |  %d Kerberoastable", len(asrep), len(kerb))

	results := output.Results{
		Summary: output.Summary{
			TotalUsers:           len(users),
			ASREPCandidates:      len(asrep),
			KerberoastCandidates: len(kerb),
		},
		Candidates: all,
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
	if *adv || *rbcd || *s4u || *dcsync || *pkinit {
		runAdvanced(client, cfg, *adv, *audit, *rbcd, *s4u, *dcsync, *pkinit, target, bindUser, *pass, *domain)
	}

	// ── output ───────────────────────────────────────────────────────────
	writeResults(results, all, cfg, *outFile, *csvOut, *siem, *jsonOnly)
}

// ═══════════════════════════════════════════════════════════════════════════
// HELP
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
	fmt.Printf("  %s# Offline file analysis%s\n", g, r)
	fmt.Printf("  %skerb-sleuth -f exported_users.csv -o report.json --csv%s\n", h, r)
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
	fmt.Println("    -k                    Skip TLS cert verify  (like curl -k)")
	fmt.Println("    --timeout <dur>       Connection timeout  (default 10s)")
	fmt.Println()
	fmt.Println("  Output:")
	fmt.Println("    -o  <file>            Output file  (default: <target>_results.json)")
	fmt.Println("    --csv                 Also write CSV")
	fmt.Println("    --siem                Also write Sigma rules")
	fmt.Println("    --json                Print JSON to stdout")
	fmt.Println()
	fmt.Println("  Attacks:")
	fmt.Println("    --crack               Extract hashes + crack  (needs --yes)")
	fmt.Println("    -w  <wordlist>        Wordlist  (default: rockyou.txt)")
	fmt.Println("    --real                Real Kerberos  AS-REQ/TGS-REQ  (needs --yes)")
	fmt.Println()
	fmt.Println("  Advanced:")
	fmt.Println("    -A                    Run ALL advanced modules")
	fmt.Println("    --audit               Audit mode  (read-only)")
	fmt.Println("    --rbcd                RBCD enumeration")
	fmt.Println("    --s4u                 S4U delegation")
	fmt.Println("    --dcsync              DCSync rights")
	fmt.Println("    --pkinit              PKINIT / AD CS")
	fmt.Println()
	fmt.Println("  Other:")
	fmt.Println("    -f  <file>            Offline AD export  (CSV / JSON / LDIF)")
	fmt.Println("    --yes                 Confirm authorization")
	fmt.Println("    --config <file>       Config YAML  (default: configs/defaults.yml)")
	fmt.Println()
	fmt.Printf("  %sWARNING: Only use on systems you own or have written permission to test.%s\n", util.Red, r)
}

// ═══════════════════════════════════════════════════════════════════════════
// CONNECTION
// ═══════════════════════════════════════════════════════════════════════════

// smartConnect tries the user-specified mode, or auto-detects LDAP→LDAPS.
func smartConnect(opts krb.ConnectOptions) (*krb.LDAPClient, error) {
	// If user explicitly asked for --ssl or --starttls, use exactly that
	if opts.UseSSL || opts.StartTLS {
		return krb.Connect(opts)
	}

	// Auto-detect: try plain LDAP first (faster), then LDAPS
	log.Printf("[*] Auto-detecting connection to %s …", opts.Target)

	client, err := krb.Connect(opts)
	if err == nil {
		return client, nil
	}

	log.Printf("[!] LDAP failed (%v), trying LDAPS …", err)
	opts.UseSSL = true
	opts.Insecure = true // self-signed certs are common on lab boxes
	client, err = krb.Connect(opts)
	if err == nil {
		return client, nil
	}

	return nil, fmt.Errorf("could not connect to %s via LDAP or LDAPS.\n"+
		"    Try: kerb-sleuth %s -u <user> -p <pass> --ssl -k\n"+
		"    Error: %v", opts.Target, opts.Target, err)
}

// ═══════════════════════════════════════════════════════════════════════════
// OFFLINE ANALYSIS
// ═══════════════════════════════════════════════════════════════════════════

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

	log.Printf("[+] %d AS-REP roastable  |  %d Kerberoastable", len(asrep), len(kerb))

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
	}

	writeResults(results, all, cfg, outFile, csvOut, siemOut, jsonOnly)
}

// ═══════════════════════════════════════════════════════════════════════════
// HASH EXTRACTION & CRACKING
// ═══════════════════════════════════════════════════════════════════════════

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
				log.Printf("[x] AS-REP fail for %s: %v", c.SamAccountName, err)
				continue
			}
			asrepHashes = append(asrepHashes, h.Hash)
			log.Printf("[+] AS-REP hash: %s", c.SamAccountName)

		case "KERBEROAST":
			for _, spn := range c.SPNs {
				h, err := client.ExtractKerberoastHash(c.SamAccountName, domainInfo.DomainName, spn)
				if err != nil {
					log.Printf("[x] Kerberoast fail for %s: %v", c.SamAccountName, err)
					continue
				}
				kerbHashes = append(kerbHashes, h.Hash)
				log.Printf("[+] TGS hash: %s (%s)", c.SamAccountName, spn)
			}
		}
	}

	// Write & crack AS-REP hashes
	if len(asrepHashes) > 0 {
		f := filepath.Join(hashDir, "asrep.txt")
		writeHashes(f, asrepHashes)
		log.Printf("[+] %d AS-REP hashes → %s", len(asrepHashes), f)
		crackAndShow("asrep", f, wordlistPath)
	}

	// Write & crack Kerberoast hashes
	if len(kerbHashes) > 0 {
		f := filepath.Join(hashDir, "kerberoast.txt")
		writeHashes(f, kerbHashes)
		log.Printf("[+] %d Kerberoast hashes → %s", len(kerbHashes), f)
		crackAndShow("kerberoast", f, wordlistPath)
	}
}

func writeHashes(path string, hashes []string) {
	f, err := os.Create(path)
	if err != nil {
		log.Printf("[x] Failed to write %s: %v", path, err)
		return
	}
	defer f.Close()
	for _, h := range hashes {
		fmt.Fprintln(f, h)
	}
}

func crackAndShow(attackType, hashFile, wordlist string) {
	results, err := cracker.CrackHashes(hashFile, wordlist, attackType)
	if err != nil {
		log.Printf("[!] %s cracking failed: %v", attackType, err)
		return
	}
	for hash, pw := range results {
		short := hash
		if len(hash) > 25 {
			short = hash[:25]
		}
		log.Printf("[+] CRACKED: %s… → %s", short, pw)
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// REAL KERBEROS PROTOCOL
// ═══════════════════════════════════════════════════════════════════════════

func runRealKerberos(target, user, pass string) {
	kc, err := kerberos.NewKerberosClient(target, target)
	if err != nil {
		log.Printf("[x] Kerberos client: %v", err)
		return
	}

	if user != "" && pass != "" {
		if err := kc.AuthenticateWithPassword(user, pass); err != nil {
			log.Printf("[x] Kerberos auth: %v", err)
			return
		}
	}

	log.Printf("[+] Real Kerberos protocol ready")
}

// ═══════════════════════════════════════════════════════════════════════════
// ADVANCED MODULES
// ═══════════════════════════════════════════════════════════════════════════

func runAdvanced(client *krb.LDAPClient, cfg *triage.Config, all, auditMode, rbcd, s4u, dcsync, pkinit bool, target, user, pass, domain string) {
	log.Printf("[*] Running advanced analysis …")

	outDir := "advanced_results"
	a := advanced.NewAdvancedAnalyzer(client, auditMode, false, outDir, target, user, pass, domain)

	if all {
		if err := a.RunFullAnalysis(); err != nil {
			log.Printf("[x] Full analysis: %v", err)
		}
		return
	}

	if rbcd {
		if err := a.RunRBCDAnalysis(); err != nil {
			log.Printf("[x] RBCD: %v", err)
		}
	}
	if s4u {
		if err := a.RunS4UAnalysis(); err != nil {
			log.Printf("[x] S4U: %v", err)
		}
	}
	if dcsync {
		if err := a.RunDCSyncAnalysis(); err != nil {
			log.Printf("[x] DCSync: %v", err)
		}
	}
	if pkinit {
		if err := a.RunPKINITAnalysis(); err != nil {
			log.Printf("[x] PKINIT: %v", err)
		}
	}

	log.Printf("[+] Advanced results → %s/", outDir)
}

// ═══════════════════════════════════════════════════════════════════════════
// OUTPUT
// ═══════════════════════════════════════════════════════════════════════════

func writeResults(results output.Results, candidates []krb.Candidate, cfg *triage.Config, outFile string, csvOut, siemOut, jsonOnly bool) {
	// Count severity
	hi, med, lo := 0, 0, 0
	for _, c := range candidates {
		switch {
		case c.Score >= cfg.Thresholds.High:
			hi++
		case c.Score >= cfg.Thresholds.Medium:
			med++
		default:
			lo++
		}
	}

	if jsonOnly {
		data, _ := json.MarshalIndent(results, "", "  ")
		fmt.Println(string(data))
	} else {
		if err := output.WriteJSON(outFile, results); err != nil {
			log.Fatalf("[x] Write failed: %v", err)
		}
		log.Printf("[+] Results → %s", outFile)
	}

	if csvOut {
		csvFile := strings.TrimSuffix(outFile, ".json") + ".csv"
		if err := output.WriteCSV(csvFile, results); err != nil {
			log.Printf("[!] CSV: %v", err)
		} else {
			log.Printf("[+] CSV    → %s", csvFile)
		}
	}

	if siemOut {
		sigmaFile := strings.TrimSuffix(outFile, ".json") + "_sigma.yml"
		if err := output.WriteSigmaRules(sigmaFile, results); err != nil {
			log.Printf("[!] Sigma: %v", err)
		} else {
			log.Printf("[+] Sigma  → %s", sigmaFile)
		}
	}

	// Summary
	log.Printf("[+] Done: %d candidates  (%s%d high%s / %d med / %d low)",
		len(candidates), util.Red, hi, util.Reset, med, lo)

	if hi > 0 {
		log.Printf("[!] %s%d HIGH RISK targets — check %s%s", util.Red, hi, outFile, util.Reset)
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════════════

func loadConfigSafe(path string) *triage.Config {
	data, err := os.ReadFile(path)
	if err != nil {
		return triage.DefaultConfig()
	}
	var cfg triage.Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return triage.DefaultConfig()
	}
	return &cfg
}
