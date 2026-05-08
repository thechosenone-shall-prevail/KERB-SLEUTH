package output

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// WritePDFReport generates a PDF report from the HTML report using headless Chrome
func WritePDFReport(htmlPath, pdfPath string) error {
	// Check if wkhtmltopdf or chrome/chromium is available
	if err := checkPDFTools(); err != nil {
		return fmt.Errorf("PDF generation tools not available: %v", err)
	}

	// Try Chrome/Chromium first (better rendering)
	if err := generatePDFWithChrome(htmlPath, pdfPath); err == nil {
		log.Printf("[+] PDF report generated using Chrome: %s", pdfPath)
		return nil
	}

	// Fallback to wkhtmltopdf
	if err := generatePDFWithWKHTML(htmlPath, pdfPath); err == nil {
		log.Printf("[+] PDF report generated using wkhtmltopdf: %s", pdfPath)
		return nil
	}

	return fmt.Errorf("failed to generate PDF with available tools")
}

// checkPDFTools checks if PDF generation tools are available
func checkPDFTools() error {
	// Check for Chrome/Chromium
	chromePaths := []string{
		"chrome",
		"chromium",
		"google-chrome",
		"chromium-browser",
		"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
		"C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe",
	}

	for _, path := range chromePaths {
		if _, err := exec.LookPath(path); err == nil {
			return nil
		}
	}

	// Check for wkhtmltopdf
	if _, err := exec.LookPath("wkhtmltopdf"); err == nil {
		return nil
	}

	return fmt.Errorf("no PDF generation tools found (Chrome or wkhtmltopdf)")
}

// generatePDFWithChrome uses headless Chrome to generate PDF
func generatePDFWithChrome(htmlPath, pdfPath string) error {
	chromePaths := []string{
		"chrome",
		"chromium",
		"google-chrome",
		"chromium-browser",
		"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
		"C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe",
	}

	var chromePath string
	for _, path := range chromePaths {
		if _, err := exec.LookPath(path); err == nil {
			chromePath = path
			break
		}
		// Check if file exists directly
		if _, err := os.Stat(path); err == nil {
			chromePath = path
			break
		}
	}

	if chromePath == "" {
		return fmt.Errorf("chrome not found")
	}

	// Ensure paths are absolute
	absHTMLPath, err := filepath.Abs(htmlPath)
	if err != nil {
		return err
	}

	absPDFPath, err := filepath.Abs(pdfPath)
	if err != nil {
		return err
	}

	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(absPDFPath), 0755); err != nil {
		return err
	}

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Chrome command for PDF generation
	args := []string{
		"--headless",
		"--disable-gpu",
		"--no-sandbox",
		"--disable-dev-shm-usage",
		"--print-to-pdf=" + absPDFPath,
		"--print-to-pdf-no-header",
		"file:///" + filepath.ToSlash(absHTMLPath),
	}

	cmd := exec.CommandContext(ctx, chromePath, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("chrome execution failed: %v, output: %s", err, string(output))
	}

	// Verify PDF was created
	if _, err := os.Stat(absPDFPath); os.IsNotExist(err) {
		return fmt.Errorf("PDF file was not created")
	}

	return nil
}

// generatePDFWithWKHTML uses wkhtmltopdf to generate PDF
func generatePDFWithWKHTML(htmlPath, pdfPath string) error {
	if _, err := exec.LookPath("wkhtmltopdf"); err != nil {
		return fmt.Errorf("wkhtmltopdf not found")
	}

	// Ensure paths are absolute
	absHTMLPath, err := filepath.Abs(htmlPath)
	if err != nil {
		return err
	}

	absPDFPath, err := filepath.Abs(pdfPath)
	if err != nil {
		return err
	}

	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(absPDFPath), 0755); err != nil {
		return err
	}

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// wkhtmltopdf command
	args := []string{
		"--enable-local-file-access",
		"--print-media-type",
		"--no-stop-slow-scripts",
		"--javascript-delay", "2000",
		absHTMLPath,
		absPDFPath,
	}

	cmd := exec.CommandContext(ctx, "wkhtmltopdf", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("wkhtmltopdf execution failed: %v, output: %s", err, string(output))
	}

	// Verify PDF was created
	if _, err := os.Stat(absPDFPath); os.IsNotExist(err) {
		return fmt.Errorf("PDF file was not created")
	}

	return nil
}
