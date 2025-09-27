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
