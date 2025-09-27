package cracker

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

func InvokeCracker(hashfile, wordlist string) error {
	// Check for cracking tools
	crackerPath, crackerType := findCracker()
	if crackerPath == "" {
		return fmt.Errorf("no cracking tool found. Please install hashcat or john")
	}

	// Verify hash file exists
	if _, err := os.Stat(hashfile); err != nil {
		return fmt.Errorf("hash file not found: %s", hashfile)
	}

	// Verify wordlist exists
	if _, err := os.Stat(wordlist); err != nil {
		return fmt.Errorf("wordlist not found: %s", wordlist)
	}

	// Create log file
	logDir := filepath.Dir(hashfile)
	logFile := filepath.Join(logDir, "cracker.log")

	log, err := os.Create(logFile)
	if err != nil {
		return err
	}
	defer log.Close()

	fmt.Fprintf(log, "Starting %s cracking session\n", crackerType)
	fmt.Fprintf(log, "Hash file: %s\n", hashfile)
	fmt.Fprintf(log, "Wordlist: %s\n", wordlist)
	fmt.Fprintf(log, "Command: %s\n", crackerPath)
	fmt.Fprintf(log, "---\n")

	var cmd *exec.Cmd

	switch crackerType {
	case "hashcat":
		// Hashcat command for Kerberos hashes
		cmd = exec.Command(crackerPath,
			"-m", "18200", // AS-REP mode
			"-a", "0", // Straight attack
			hashfile,
			wordlist,
			"--force", // Force run
			"--quiet", // Quiet mode
		)
	case "john":
		// John the Ripper command
		cmd = exec.Command(crackerPath,
			"--wordlist="+wordlist,
			hashfile,
		)
	}

	// Set output to log file
	cmd.Stdout = log
	cmd.Stderr = log

	fmt.Println("Starting cracking process...")
	fmt.Printf("Check progress in: %s\n", logFile)

	// Run the command
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(log, "\nError: %v\n", err)
		return fmt.Errorf("cracking failed: %v (check %s for details)", err, logFile)
	}

	fmt.Fprintf(log, "\nCracking session completed\n")
	fmt.Println("Cracking completed. Check results in:", logFile)

	// Try to extract results
	resultsFile := filepath.Join(logDir, "cracked_results.txt")
	extractResults(crackerType, crackerPath, hashfile, resultsFile)

	return nil
}

// CrackASREP cracks AS-REP hashes using hashcat mode 18200
func CrackASREP(hashfile, wordlist string) error {
	return crackWithMode(hashfile, wordlist, "18200", "AS-REP")
}

// CrackKerberoast cracks Kerberoast hashes using hashcat mode 13100
func CrackKerberoast(hashfile, wordlist string) error {
	return crackWithMode(hashfile, wordlist, "13100", "Kerberoast")
}

// crackWithMode performs cracking with specific hashcat mode
func crackWithMode(hashfile, wordlist, mode, attackType string) error {
	// Check for cracking tools
	crackerPath, crackerType := findCracker()
	if crackerPath == "" {
		return fmt.Errorf("no cracking tool found. Please install hashcat or john")
	}

	// Verify hash file exists
	if _, err := os.Stat(hashfile); err != nil {
		return fmt.Errorf("hash file not found: %s", hashfile)
	}

	// Verify wordlist exists - use default if specified doesn't exist
	if _, err := os.Stat(wordlist); err != nil {
		fmt.Printf("⚠️ Wordlist %s not found, trying common locations...\n", wordlist)

		// Try common wordlist locations
		commonWordlists := []string{
			"/usr/share/wordlists/rockyou.txt",
			"/usr/share/dict/words",
			"/opt/wordlists/rockyou.txt",
		}

		found := false
		for _, w := range commonWordlists {
			if _, err := os.Stat(w); err == nil {
				fmt.Printf("✅ Using wordlist: %s\n", w)
				wordlist = w
				found = true
				break
			}
		}

		if !found {
			return fmt.Errorf("no wordlist found. Please install rockyou.txt or specify valid wordlist path")
		}
	}

	// Create results directory
	resultDir := filepath.Join(filepath.Dir(hashfile), "results")
	if err := os.MkdirAll(resultDir, 0755); err != nil {
		return fmt.Errorf("failed to create results directory: %v", err)
	}

	// Create log file
	logFile := filepath.Join(resultDir, fmt.Sprintf("crack_%s.log", attackType))
	potFile := filepath.Join(resultDir, fmt.Sprintf("cracked_%s.pot", attackType))

	log, err := os.Create(logFile)
	if err != nil {
		return err
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
		cmd = exec.Command(crackerPath,
			"--wordlist="+wordlist,
			"--format=krb5asrep", // Adjust format as needed
			hashfile,
		)
	}

	// Set output to log file
	cmd.Stdout = log
	cmd.Stderr = log

	fmt.Printf("🔨 Starting %s cracking process...\n", attackType)
	fmt.Printf("📄 Progress log: %s\n", logFile)

	// Run the command
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(log, "\nError: %v\n", err)
		return fmt.Errorf("%s cracking failed: %v (check %s for details)", attackType, err, logFile)
	}

	fmt.Fprintf(log, "\n%s cracking session completed\n", attackType)

	// Check for cracked passwords
	if _, err := os.Stat(potFile); err == nil {
		fmt.Printf("✅ %s cracking completed! Results in: %s\n", attackType, potFile)

		// Read and display results
		if content, err := os.ReadFile(potFile); err == nil && len(content) > 0 {
			fmt.Printf("🎉 CRACKED PASSWORDS FOUND:\n%s\n", string(content))
		}
	} else {
		fmt.Printf("❌ %s cracking completed but no passwords cracked\n", attackType)
	}

	return nil
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

func extractResults(crackerType, crackerPath, hashfile, outputFile string) {
	var cmd *exec.Cmd

	switch crackerType {
	case "hashcat":
		cmd = exec.Command(crackerPath, "--show", hashfile)
	case "john":
		cmd = exec.Command(crackerPath, "--show", hashfile)
	}

	output, err := cmd.Output()
	if err != nil {
		return
	}

	if len(output) > 0 {
		os.WriteFile(outputFile, output, 0644)
		fmt.Println("Cracked passwords saved to:", outputFile)
	}
}
