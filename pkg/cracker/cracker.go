package cracker

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// CrackHashes is the main entry point for hash cracking
func CrackHashes(hashfile, wordlist, attackType string) (map[string]string, error) {
	switch strings.ToLower(attackType) {
	case "asrep", "as-rep":
		return CrackASREP(hashfile, wordlist)
	case "kerberoast", "tgs":
		return CrackKerberoast(hashfile, wordlist)
	default:
		return nil, fmt.Errorf("unsupported attack type: %s", attackType)
	}
}

// CrackASREP cracks AS-REP hashes using hashcat mode 18200
func CrackASREP(hashfile, wordlist string) (map[string]string, error) {
	return crackWithMode(hashfile, wordlist, "18200", "AS-REP")
}

// CrackKerberoast cracks Kerberoast hashes using hashcat mode 13100
func CrackKerberoast(hashfile, wordlist string) (map[string]string, error) {
	return crackWithMode(hashfile, wordlist, "13100", "Kerberoast")
}

// crackWithMode performs cracking with specific hashcat mode
func crackWithMode(hashfile, wordlist, mode, attackType string) (map[string]string, error) {
	// Check for cracking tools
	crackerPath, crackerType := findCracker()
	if crackerPath == "" {
		return nil, fmt.Errorf("no cracking tool found. Please install hashcat or john")
	}

	// Verify hash file exists
	if _, err := os.Stat(hashfile); err != nil {
		return nil, fmt.Errorf("hash file not found: %s", hashfile)
	}

	// Verify wordlist exists - use default if specified doesn't exist
	if _, err := os.Stat(wordlist); err != nil {
		fmt.Printf("[!] Wordlist %s not found, trying common locations...\n", wordlist)

		// Try common wordlist locations
		commonWordlists := []string{
			"/usr/share/wordlists/rockyou.txt",
			"/usr/share/dict/words",
			"/opt/wordlists/rockyou.txt",
			"C:\\wordlists\\rockyou.txt",
		}

		found := false
		for _, w := range commonWordlists {
			if _, err := os.Stat(w); err == nil {
				fmt.Printf("[+] Using wordlist: %s\n", w)
				wordlist = w
				found = true
				break
			}
		}

		if !found {
			return nil, fmt.Errorf("no wordlist found. Please install rockyou.txt or specify valid wordlist path")
		}
	}

	// Create results directory
	resultDir := filepath.Join(filepath.Dir(hashfile), "results")
	if err := os.MkdirAll(resultDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create results directory: %v", err)
	}

	// Create log file
	logFile := filepath.Join(resultDir, fmt.Sprintf("crack_%s.log", attackType))
	potFile := filepath.Join(resultDir, fmt.Sprintf("cracked_%s.pot", attackType))

	log, err := os.Create(logFile)
	if err != nil {
		return nil, err
	}
	defer log.Close()

	fmt.Fprintf(log, "Starting %s cracking session (%s)\n", attackType, crackerType)
	fmt.Fprintf(log, "Hash file: %s\n", hashfile)
	fmt.Fprintf(log, "Wordlist: %s\n", wordlist)
	fmt.Fprintf(log, "Mode: %s\n", mode)
	fmt.Fprintf(log, "---\n")

	var cmd *exec.Cmd

	switch crackerType {
	case "hashcat":
		// Hashcat command with specific mode
		cmd = exec.Command(crackerPath,
			"-m", mode,
			"-a", "0", // Straight attack
			hashfile,
			wordlist,
			"--potfile-path", potFile,
			"--force",  // Force run
			"--quiet",  // Quiet mode
			"--status", // Show status
		)
	case "john":
		// John the Ripper command
		johnFormat := "krb5asrep"
		if attackType == "Kerberoast" {
			johnFormat = "krb5tgs"
		}
		cmd = exec.Command(crackerPath,
			"--wordlist="+wordlist,
			"--format="+johnFormat,
			hashfile,
		)
	}

	// Set output to log file
	cmd.Stdout = log
	cmd.Stderr = log

	fmt.Printf("🔨 Starting %s cracking process...\n", attackType)
	fmt.Printf("[+] Progress log: %s\n", logFile)

	// Run the command
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(log, "\nError: %v\n", err)
		return nil, fmt.Errorf("%s cracking failed: %v (check %s for details)", attackType, err, logFile)
	}

	fmt.Fprintf(log, "\n%s cracking session completed\n", attackType)

	// Parse results
	results := make(map[string]string)

	// Check for cracked passwords in pot file
	if _, err := os.Stat(potFile); err == nil {
		if content, err := os.ReadFile(potFile); err == nil && len(content) > 0 {
			fmt.Printf("[+] %s cracking completed! Results in: %s\n", attackType, potFile)

			// Parse pot file format (hash:password)
			lines := strings.Split(string(content), "\n")
			for _, line := range lines {
				if strings.TrimSpace(line) == "" {
					continue
				}
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					results[parts[0]] = parts[1]
				}
			}

			fmt.Printf("[+] CRACKED %d PASSWORDS:\n", len(results))
			for hash, password := range results {
				fmt.Printf("   %s... => %s\n", hash[:20], password)
			}
		}
	} else {
		fmt.Printf("[x] %s cracking completed but no passwords cracked\n", attackType)
	}

	return results, nil
}

// InvokeCracker is the legacy function for backward compatibility
func InvokeCracker(hashfile, wordlist string) error {
	// Determine attack type based on file name
	attackType := "asrep"
	if strings.Contains(strings.ToLower(hashfile), "kerberoast") {
		attackType = "kerberoast"
	}

	_, err := CrackHashes(hashfile, wordlist, attackType)
	return err
}

func findCracker() (string, string) {
	// Check for hashcat
	if path, err := exec.LookPath("hashcat"); err == nil {
		return path, "hashcat"
	}

	// Check for john
	if path, err := exec.LookPath("john"); err == nil {
		return path, "john"
	}

	return "", ""
}
