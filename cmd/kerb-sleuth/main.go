package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/yourusername/kerb-sleuth/pkg/cracker"
	"github.com/yourusername/kerb-sleuth/pkg/ingest"
	"github.com/yourusername/kerb-sleuth/pkg/krb"
	"github.com/yourusername/kerb-sleuth/pkg/output"
	"github.com/yourusername/kerb-sleuth/pkg/triage"
	"github.com/yourusername/kerb-sleuth/pkg/util"
	"gopkg.in/yaml.v3"
)

var (
	version = "1.0.0"

	// scan command flags
	adFile     = flag.String("ad", "", "Path to AD export file (CSV/LDIF/JSON)")
	krbLogs    = flag.String("krb-logs", "", "Path to Kerberos event logs JSON")
	pcapFile   = flag.String("pcap", "", "Path to pcap file (requires pcap build tag)")
	outFile    = flag.String("out", "results.json", "Output JSON file path")
	csvOutput  = flag.Bool("csv", false, "Produce CSV summary")
	siemOutput = flag.Bool("siem", false, "Produce Sigma rules")
	configFile = flag.String("config", "configs/defaults.yml", "Path to config file")

	// cracking flags
	crack      = flag.Bool("crack", false, "Enable hash export and cracking")
	wordlist   = flag.String("wordlist", "/usr/share/wordlists/rockyou.txt", "Path to wordlist")
	authorized = flag.Bool("i-am-authorized", false, "Confirm authorization for sensitive operations")

	// live scan flags
	ldapURL  = flag.String("ldap", "", "LDAP/LDAPS URL for live scan")
	bindUser = flag.String("bind-user", "", "LDAP bind username")
	bindPass = flag.String("bind-pass", "", "LDAP bind password")

	// simulate flags
	dataset = flag.String("dataset", "", "Dataset to generate (small/medium/large)")
)

func main() {
	// Display the banner first for visual appeal
	util.DisplayBanner(version)

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]
	os.Args = append([]string{os.Args[0]}, os.Args[2:]...)
	flag.Parse()

	switch command {
	case "scan":
		runScan()
	case "simulate":
		runSimulate()
	case "live-scan":
		runLiveScan()
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
	fmt.Printf("%s╔══════════════════════════════════════════════════════════════════════════════════╗%s\n", util.DarkRed, util.Reset)
	fmt.Printf("%s║                                  USAGE GUIDE                                    ║%s\n", util.DarkRed, util.Reset)
	fmt.Printf("%s╚══════════════════════════════════════════════════════════════════════════════════╝%s\n", util.DarkRed, util.Reset)
	fmt.Println()
	fmt.Printf("%sUSAGE:%s\n", util.Bold, util.Reset)
	fmt.Println("    kerb-sleuth <command> [flags]")
	fmt.Println()

	fmt.Printf("%sCOMMANDS:%s\n", util.Bold, util.Reset)
	fmt.Println("    scan        Scan AD export files for AS-REP and Kerberoastable accounts")
	fmt.Println("    simulate    Generate synthetic test data")
	fmt.Println("    live-scan   Perform live LDAP scan (requires authorization)")
	fmt.Println("    version     Show version information")
	fmt.Println("    help        Show this help message")
	fmt.Println()

	fmt.Printf("%sSCAN FLAGS:%s\n", util.Bold, util.Reset)
	fmt.Println("    --ad <file>         Path to AD export file (CSV/LDIF/JSON) [required]")
	fmt.Println("    --krb-logs <file>   Path to Kerberos event logs JSON")
	fmt.Println("    --pcap <file>       Path to pcap file (requires pcap build tag)")
	fmt.Println("    --out <file>        Output JSON file (default: results.json)")
	fmt.Println("    --csv               Produce CSV summary")
	fmt.Println("    --siem              Produce Sigma rules")
	fmt.Println("    --config <file>     Path to config file (default: configs/defaults.yml)")
	fmt.Println()

	fmt.Printf("%sCRACKING FLAGS (requires --i-am-authorized):%s\n", util.Bold, util.Reset)
	fmt.Println("    --crack             Enable hash export and cracking")
	fmt.Println("    --wordlist <file>   Path to wordlist (default: /usr/share/wordlists/rockyou.txt)")
	fmt.Println("    --i-am-authorized   Confirm authorization for sensitive operations")
	fmt.Println()

	fmt.Printf("%sLIVE SCAN FLAGS (requires --i-am-authorized):%s\n", util.Bold, util.Reset)
	fmt.Println("    --ldap <url>        LDAP/LDAPS URL")
	fmt.Println("    --bind-user <user>  LDAP bind username")
	fmt.Println("    --bind-pass <pass>  LDAP bind password")
	fmt.Println()

	fmt.Printf("%sSIMULATE FLAGS:%s\n", util.Bold, util.Reset)
	fmt.Println("    --dataset <size>    Dataset to generate (small/medium/large)")
	fmt.Println("    --out <dir>         Output directory")
	fmt.Println()

	fmt.Printf("%sEXAMPLES:%s\n", util.Bold, util.Reset)
	fmt.Println("    kerb-sleuth scan --ad users.csv --out results.json")
	fmt.Println("    kerb-sleuth scan --ad users.csv --crack --i-am-authorized")
	fmt.Println("    kerb-sleuth simulate --dataset small --out tests/sample_data/")
	fmt.Println("    kerb-sleuth live-scan --ldap ldaps://dc.corp --bind-user svc_read --bind-pass '***' --i-am-authorized")
	fmt.Println()

	fmt.Printf("%sWARNING:%s\n", util.DarkRed+util.Bold, util.Reset)
	fmt.Printf("%s    This tool is for authorized security assessments only.\n", util.DarkRed)
	fmt.Printf("    Ensure you have proper authorization before using --crack or live-scan features.%s\n", util.Reset)
}

func runScan() {
	if *adFile == "" {
		log.Fatal("--ad flag is required for scan command")
	}

	if *crack && !*authorized {
		log.Fatal("--crack requires --i-am-authorized flag")
	}

	// Load config
	cfg, err := loadConfig(*configFile)
	if err != nil {
		log.Printf("Warning: Could not load config file %s, using defaults: %v", *configFile, err)
		cfg = triage.DefaultConfig()
	}

	// Parse AD export
	users, err := ingest.ParseAD(*adFile)
	if err != nil {
		log.Fatalf("Failed to parse AD file: %v", err)
	}

	log.Printf("Parsed %d users from %s", len(users), *adFile)

	// Find candidates
	asrepCandidates := krb.FindASREPCandidates(users)
	kerberoastCandidates := krb.FindKerberoastCandidates(users)

	log.Printf("Found %d AS-REP candidates", len(asrepCandidates))
	log.Printf("Found %d Kerberoast candidates", len(kerberoastCandidates))

	// Score candidates
	scoredCandidates := triage.ScoreCandidates(asrepCandidates, kerberoastCandidates, cfg)

	// Prepare results
	results := output.Results{
		Summary: output.Summary{
			TotalUsers:           len(users),
			ASREPCandidates:      len(asrepCandidates),
			KerberoastCandidates: len(kerberoastCandidates),
		},
		Candidates: scoredCandidates,
	}

	// Write JSON output
	if err := output.WriteJSON(*outFile, results); err != nil {
		log.Fatalf("Failed to write JSON output: %v", err)
	}
	log.Printf("Results written to %s", *outFile)

	// Write CSV if requested
	if *csvOutput {
		csvFile := filepath.Join(filepath.Dir(*outFile), "summary.csv")
		if err := output.WriteCSV(csvFile, results); err != nil {
			log.Printf("Failed to write CSV output: %v", err)
		} else {
			log.Printf("CSV summary written to %s", csvFile)
		}
	}

	// Write Sigma rules if requested
	if *siemOutput {
		sigmaFile := filepath.Join(filepath.Dir(*outFile), "sigma_rules.yml")
		if err := output.WriteSigmaRules(sigmaFile, results); err != nil {
			log.Printf("Failed to write Sigma rules: %v", err)
		} else {
			log.Printf("Sigma rules written to %s", sigmaFile)
		}
	}

	// Export hashes and crack if requested
	if *crack && *authorized {
		exportDir := filepath.Join(filepath.Dir(*outFile), "exports")
		os.MkdirAll(exportDir, 0755)

		hashFile := filepath.Join(exportDir, "kerb_hashes.txt")
		if err := output.WriteHashExport(hashFile, results); err != nil {
			log.Printf("Failed to export hashes: %v", err)
		} else {
			log.Printf("Hashes exported to %s", hashFile)

			// Invoke cracker
			if err := cracker.InvokeCracker(hashFile, *wordlist); err != nil {
				log.Printf("Cracking failed: %v", err)
			}
		}
	}
}

func runSimulate() {
	if *dataset == "" {
		*dataset = "small"
	}

	if *outFile == "results.json" {
		*outFile = "tests/sample_data"
	}

	os.MkdirAll(*outFile, 0755)

	// Generate sample data
	if err := generateSampleData(*dataset, *outFile); err != nil {
		log.Fatalf("Failed to generate sample data: %v", err)
	}

	log.Printf("Sample data generated in %s", *outFile)
}

func runLiveScan() {
	if !*authorized {
		log.Fatal("live-scan requires --i-am-authorized flag")
	}

	if *ldapURL == "" || *bindUser == "" || *bindPass == "" {
		log.Fatal("--ldap, --bind-user, and --bind-pass are required for live-scan")
	}

	log.Println("Live scan not yet implemented in this sprint")
	os.Exit(1)
}

func loadConfig(path string) (*triage.Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg triage.Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}

func generateSampleData(dataset, outDir string) error {
	// Generate sample CSV
	csvPath := filepath.Join(outDir, "users_small.csv")
	csvContent := `sAMAccountName,distinguishedName,DoesNotRequirePreAuth,userAccountControl,servicePrincipalName,pwdLastSet,lastLogon,memberOf
alice,CN=alice;OU=Users;DC=corp;DC=local,False,512,,,1622505600,1625097600,
bob,CN=bob;OU=Users;DC=corp;DC=local,False,512,,,1622505600,1625097600,CN=Domain Users
backupsvc,CN=backupsvc;OU=Service Accounts;DC=corp;DC=local,True,4260352,,,1590969600,1625097600,CN=Backup Operators
sqlsvc,CN=sqlsvc;OU=Service Accounts;DC=corp;DC=local,False,512,MSSQLSvc/sql01.corp.local:1433;MSSQLSvc/sql01.corp.local,1590969600,1625097600,CN=DBAdmins
websvc,CN=websvc;OU=Service Accounts;DC=corp;DC=local,False,512,HTTP/web01.corp.local;HTTP/web01.corp.local:80,1622505600,1625097600,
adminuser,CN=adminuser;OU=Users;DC=corp;DC=local,True,4260352,,,1590969600,1625097600,CN=Domain Admins;CN=Enterprise Admins
machine01$,CN=machine01;OU=Computers;DC=corp;DC=local,False,4096,HOST/machine01.corp.local,,1625097600,
disableduser,CN=disableduser;OU=Users;DC=corp;DC=local,False,514,,,1622505600,0,
`

	if err := os.WriteFile(csvPath, []byte(csvContent), 0644); err != nil {
		return err
	}

	// Generate sample Kerberos events
	eventsPath := filepath.Join(outDir, "krb_events_small.json")
	eventsContent := `[
  {
    "EventID": 4768,
    "TimeGenerated": "2024-01-15T10:30:00Z",
    "AccountName": "backupsvc",
    "ServiceName": "krbtgt",
    "PreAuthType": 0,
    "Result": "0x0",
    "ClientAddress": "192.168.1.100"
  },
  {
    "EventID": 4769,
    "TimeGenerated": "2024-01-15T10:35:00Z",
    "AccountName": "sqlsvc",
    "ServiceName": "MSSQLSvc/sql01.corp.local:1433",
    "TicketOptions": "0x40810000",
    "Result": "0x0",
    "ClientAddress": "192.168.1.101"
  },
  {
    "EventID": 4768,
    "TimeGenerated": "2024-01-15T10:40:00Z",
    "AccountName": "adminuser",
    "ServiceName": "krbtgt",
    "PreAuthType": 0,
    "Result": "0x0",
    "ClientAddress": "192.168.1.102"
  }
]`

	if err := os.WriteFile(eventsPath, []byte(eventsContent), 0644); err != nil {
		return err
	}

	// Generate sample README
	readmePath := filepath.Join(outDir, "README.md")
	readmeContent := `# Sample Test Data

This directory contains synthetic test data for kerb-sleuth testing.

## Files:
- **users_small.csv**: Sample Active Directory user export
- **krb_events_small.json**: Sample Kerberos event logs

## Test Accounts:
- **backupsvc**: AS-REP vulnerable (DoesNotRequirePreAuth=True)
- **sqlsvc**: Kerberoastable (has SQL Server SPNs)
- **websvc**: Kerberoastable (has HTTP SPNs)
- **adminuser**: AS-REP vulnerable admin account
- **machine01$**: Machine account (should be filtered)
- **disableduser**: Disabled account (should be filtered)
`

	return os.WriteFile(readmePath, []byte(readmeContent), 0644)
}
