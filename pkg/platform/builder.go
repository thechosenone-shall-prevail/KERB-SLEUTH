package platform

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// PlatformInfo represents platform-specific information
type PlatformInfo struct {
	OS             string
	Architecture   string
	Version        string
	Kernel         string
	Shell          string
	PackageManager string
}

// CrossPlatformBuilder handles cross-platform builds
type CrossPlatformBuilder struct {
	Targets []BuildTarget
	Config  BuildConfig
}

// BuildTarget represents a build target
type BuildTarget struct {
	OS   string
	Arch string
	Name string
}

// BuildConfig represents build configuration
type BuildConfig struct {
	OutputDir    string
	Version      string
	LDFlags      string
	BuildTags    string
	RaceDetector bool
	Optimize     bool
}

// NewCrossPlatformBuilder creates a new cross-platform builder
func NewCrossPlatformBuilder() *CrossPlatformBuilder {
	return &CrossPlatformBuilder{
		Targets: []BuildTarget{
			{OS: "windows", Arch: "amd64", Name: "kerb-sleuth-windows-amd64.exe"},
			{OS: "linux", Arch: "amd64", Name: "kerb-sleuth-linux-amd64"},
			{OS: "darwin", Arch: "amd64", Name: "kerb-sleuth-darwin-amd64"},
			{OS: "darwin", Arch: "arm64", Name: "kerb-sleuth-darwin-arm64"},
			{OS: "linux", Arch: "arm64", Name: "kerb-sleuth-linux-arm64"},
		},
		Config: BuildConfig{
			OutputDir:    "dist",
			Version:      "1.0.0",
			LDFlags:      "-s -w",
			BuildTags:    "",
			RaceDetector: false,
			Optimize:     true,
		},
	}
}

// GetPlatformInfo returns current platform information
func GetPlatformInfo() *PlatformInfo {
	info := &PlatformInfo{
		OS:           runtime.GOOS,
		Architecture: runtime.GOARCH,
	}

	// Get OS-specific information
	switch runtime.GOOS {
	case "windows":
		info.Version = getWindowsVersion()
		info.Shell = "cmd.exe"
		info.PackageManager = "chocolatey"
	case "linux":
		info.Version = getLinuxVersion()
		info.Shell = "bash"
		info.PackageManager = getLinuxPackageManager()
	case "darwin":
		info.Version = getDarwinVersion()
		info.Shell = "zsh"
		info.PackageManager = "homebrew"
	}

	info.Kernel = getKernelVersion()

	return info
}

// BuildAll builds for all target platforms
func (cpb *CrossPlatformBuilder) BuildAll() error {
	log.Printf("🔨 Building for all platforms...")

	// Create output directory
	if err := os.MkdirAll(cpb.Config.OutputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %v", err)
	}

	// Build for each target
	for _, target := range cpb.Targets {
		log.Printf("🔨 Building for %s/%s...", target.OS, target.Arch)

		if err := cpb.buildTarget(target); err != nil {
			log.Printf("⚠️  Failed to build for %s/%s: %v", target.OS, target.Arch, err)
			continue
		}

		log.Printf("✅ Built successfully: %s", target.Name)
	}

	log.Printf("✅ Cross-platform build completed")
	return nil
}

// buildTarget builds for a specific target platform
func (cpb *CrossPlatformBuilder) buildTarget(target BuildTarget) error {
	// Set environment variables
	env := os.Environ()
	env = append(env, fmt.Sprintf("GOOS=%s", target.OS))
	env = append(env, fmt.Sprintf("GOARCH=%s", target.Arch))

	// Build command
	cmd := exec.Command("go", "build")
	cmd.Env = env
	cmd.Dir = "."

	// Add build flags
	args := []string{"build"}

	if cpb.Config.Optimize {
		args = append(args, "-ldflags", cpb.Config.LDFlags)
	}

	if cpb.Config.BuildTags != "" {
		args = append(args, "-tags", cpb.Config.BuildTags)
	}

	if cpb.Config.RaceDetector {
		args = append(args, "-race")
	}

	args = append(args, "-o", fmt.Sprintf("%s/%s", cpb.Config.OutputDir, target.Name))
	args = append(args, "./cmd/kerb-sleuth")

	cmd.Args = args

	// Execute build
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("build failed: %v\nOutput: %s", err, string(output))
	}

	return nil
}

// InstallDependencies installs platform-specific dependencies
func InstallDependencies() error {
	info := GetPlatformInfo()
	log.Printf("📦 Installing dependencies for %s/%s", info.OS, info.Architecture)

	switch info.OS {
	case "windows":
		return installWindowsDependencies()
	case "linux":
		return installLinuxDependencies()
	case "darwin":
		return installDarwinDependencies()
	default:
		return fmt.Errorf("unsupported platform: %s", info.OS)
	}
}

// installWindowsDependencies installs Windows dependencies
func installWindowsDependencies() error {
	log.Printf("📦 Installing Windows dependencies...")

	// Check if Chocolatey is installed
	if !isCommandAvailable("choco") {
		log.Printf("⚠️  Chocolatey not found. Installing...")
		if err := installChocolatey(); err != nil {
			return fmt.Errorf("failed to install Chocolatey: %v", err)
		}
	}

	// Install dependencies
	dependencies := []string{
		"git",
		"go",
		"hashcat",
		"john",
	}

	for _, dep := range dependencies {
		log.Printf("📦 Installing %s...", dep)
		cmd := exec.Command("choco", "install", dep, "-y")
		if err := cmd.Run(); err != nil {
			log.Printf("⚠️  Failed to install %s: %v", dep, err)
		}
	}

	log.Printf("✅ Windows dependencies installed")
	return nil
}

// installLinuxDependencies installs Linux dependencies
func installLinuxDependencies() error {
	log.Printf("📦 Installing Linux dependencies...")

	// Detect package manager
	packageManager := getLinuxPackageManager()
	log.Printf("📦 Using package manager: %s", packageManager)

	// Install dependencies
	dependencies := []string{
		"git",
		"golang-go",
		"hashcat",
		"john",
		"ldap-utils",
	}

	for _, dep := range dependencies {
		log.Printf("📦 Installing %s...", dep)
		var cmd *exec.Cmd

		switch packageManager {
		case "apt":
			cmd = exec.Command("sudo", "apt", "update")
			cmd.Run()
			cmd = exec.Command("sudo", "apt", "install", "-y", dep)
		case "yum":
			cmd = exec.Command("sudo", "yum", "install", "-y", dep)
		case "dnf":
			cmd = exec.Command("sudo", "dnf", "install", "-y", dep)
		case "pacman":
			cmd = exec.Command("sudo", "pacman", "-S", "--noconfirm", dep)
		default:
			log.Printf("⚠️  Unknown package manager: %s", packageManager)
			continue
		}

		if err := cmd.Run(); err != nil {
			log.Printf("⚠️  Failed to install %s: %v", dep, err)
		}
	}

	log.Printf("✅ Linux dependencies installed")
	return nil
}

// installDarwinDependencies installs macOS dependencies
func installDarwinDependencies() error {
	log.Printf("📦 Installing macOS dependencies...")

	// Check if Homebrew is installed
	if !isCommandAvailable("brew") {
		log.Printf("⚠️  Homebrew not found. Installing...")
		if err := installHomebrew(); err != nil {
			return fmt.Errorf("failed to install Homebrew: %v", err)
		}
	}

	// Install dependencies
	dependencies := []string{
		"git",
		"go",
		"hashcat",
		"john-jumbo",
		"openldap",
	}

	for _, dep := range dependencies {
		log.Printf("📦 Installing %s...", dep)
		cmd := exec.Command("brew", "install", dep)
		if err := cmd.Run(); err != nil {
			log.Printf("⚠️  Failed to install %s: %v", dep, err)
		}
	}

	log.Printf("✅ macOS dependencies installed")
	return nil
}

// Helper functions

func getWindowsVersion() string {
	cmd := exec.Command("cmd", "/c", "ver")
	output, err := cmd.Output()
	if err != nil {
		return "Unknown"
	}
	return strings.TrimSpace(string(output))
}

func getLinuxVersion() string {
	// Try to get OS release info
	cmd := exec.Command("cat", "/etc/os-release")
	output, err := cmd.Output()
	if err != nil {
		return "Unknown"
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "PRETTY_NAME=") {
			return strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), "\"")
		}
	}

	return "Unknown"
}

func getDarwinVersion() string {
	cmd := exec.Command("sw_vers", "-productVersion")
	output, err := cmd.Output()
	if err != nil {
		return "Unknown"
	}
	return strings.TrimSpace(string(output))
}

func getKernelVersion() string {
	cmd := exec.Command("uname", "-r")
	output, err := cmd.Output()
	if err != nil {
		return "Unknown"
	}
	return strings.TrimSpace(string(output))
}

func getLinuxPackageManager() string {
	if isCommandAvailable("apt") {
		return "apt"
	}
	if isCommandAvailable("yum") {
		return "yum"
	}
	if isCommandAvailable("dnf") {
		return "dnf"
	}
	if isCommandAvailable("pacman") {
		return "pacman"
	}
	return "unknown"
}

func isCommandAvailable(command string) bool {
	_, err := exec.LookPath(command)
	return err == nil
}

func installChocolatey() error {
	log.Printf("📦 Installing Chocolatey...")

	cmd := exec.Command("powershell", "-Command",
		"Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))")

	return cmd.Run()
}

func installHomebrew() error {
	log.Printf("📦 Installing Homebrew...")

	cmd := exec.Command("/bin/bash", "-c",
		"$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)")

	return cmd.Run()
}

// CreateInstallScripts creates platform-specific install scripts
func CreateInstallScripts() error {
	log.Printf("📝 Creating platform-specific install scripts...")

	// Windows install script
	windowsScript := `@echo off
echo Installing KERB-SLEUTH for Windows...
echo.

REM Check if running as administrator
net session >nul 2>&1
if %errorLevel% == 0 (
    echo Running as administrator...
) else (
    echo Please run as administrator!
    pause
    exit /b 1
)

REM Install dependencies
echo Installing dependencies...
choco install git go hashcat john -y

REM Download and install KERB-SLEUTH
echo Downloading KERB-SLEUTH...
curl -L -o kerb-sleuth-windows-amd64.exe https://github.com/thechosenone-shall-prevail/KERB-SLEUTH/releases/latest/download/kerb-sleuth-windows-amd64.exe

REM Move to system PATH
echo Installing to system PATH...
move kerb-sleuth-windows-amd64.exe C:\Windows\System32\kerb-sleuth.exe

echo.
echo Installation completed!
echo You can now run: kerb-sleuth --help
pause
`

	err := os.WriteFile("install-windows.bat", []byte(windowsScript), 0644)
	if err != nil {
		return fmt.Errorf("failed to create Windows install script: %v", err)
	}

	// Linux install script
	linuxScript := `#!/bin/bash
echo "Installing KERB-SLEUTH for Linux..."
echo

# Detect package manager
if command -v apt &> /dev/null; then
    PKG_MANAGER="apt"
elif command -v yum &> /dev/null; then
    PKG_MANAGER="yum"
elif command -v dnf &> /dev/null; then
    PKG_MANAGER="dnf"
elif command -v pacman &> /dev/null; then
    PKG_MANAGER="pacman"
else
    echo "Unknown package manager!"
    exit 1
fi

echo "Using package manager: $PKG_MANAGER"

# Install dependencies
echo "Installing dependencies..."
case $PKG_MANAGER in
    apt)
        sudo apt update
        sudo apt install -y git golang-go hashcat john ldap-utils
        ;;
    yum)
        sudo yum install -y git golang hashcat john openldap-clients
        ;;
    dnf)
        sudo dnf install -y git golang hashcat john openldap-clients
        ;;
    pacman)
        sudo pacman -S --noconfirm git go hashcat john openldap
        ;;
esac

# Download and install KERB-SLEUTH
echo "Downloading KERB-SLEUTH..."
curl -L -o kerb-sleuth-linux-amd64 https://github.com/thechosenone-shall-prevail/KERB-SLEUTH/releases/latest/download/kerb-sleuth-linux-amd64

# Make executable and move to system PATH
echo "Installing to system PATH..."
chmod +x kerb-sleuth-linux-amd64
sudo mv kerb-sleuth-linux-amd64 /usr/local/bin/kerb-sleuth

echo
echo "Installation completed!"
echo "You can now run: kerb-sleuth --help"
`

	err = os.WriteFile("install-linux.sh", []byte(linuxScript), 0755)
	if err != nil {
		return fmt.Errorf("failed to create Linux install script: %v", err)
	}

	// macOS install script
	macosScript := `#!/bin/bash
echo "Installing KERB-SLEUTH for macOS..."
echo

# Check if Homebrew is installed
if ! command -v brew &> /dev/null; then
    echo "Installing Homebrew..."
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
fi

# Install dependencies
echo "Installing dependencies..."
brew install git go hashcat john-jumbo openldap

# Download and install KERB-SLEUTH
echo "Downloading KERB-SLEUTH..."
curl -L -o kerb-sleuth-darwin-amd64 https://github.com/thechosenone-shall-prevail/KERB-SLEUTH/releases/latest/download/kerb-sleuth-darwin-amd64

# Make executable and move to system PATH
echo "Installing to system PATH..."
chmod +x kerb-sleuth-darwin-amd64
sudo mv kerb-sleuth-darwin-amd64 /usr/local/bin/kerb-sleuth

echo
echo "Installation completed!"
echo "You can now run: kerb-sleuth --help"
`

	err = os.WriteFile("install-macos.sh", []byte(macosScript), 0755)
	if err != nil {
		return fmt.Errorf("failed to create macOS install script: %v", err)
	}

	log.Printf("✅ Platform-specific install scripts created")
	return nil
}
