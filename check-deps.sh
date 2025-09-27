#!/bin/bash

# KERB-SLEUTH Dependency Checker and Installer
# Ensures all required packages are available

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}[*] KERB-SLEUTH Dependency Checker${NC}"
echo ""

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to check Go version
check_go_version() {
    if command_exists go; then
        GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
        MAJOR=$(echo $GO_VERSION | cut -d. -f1)
        MINOR=$(echo $GO_VERSION | cut -d. -f2)
        
        if [[ $MAJOR -gt 1 ]] || [[ $MAJOR -eq 1 && $MINOR -ge 20 ]]; then
            echo -e "${GREEN}✓ Go $GO_VERSION (OK)${NC}"
            return 0
        else
            echo -e "${RED}✗ Go $GO_VERSION (Need 1.20+)${NC}"
            return 1
        fi
    else
        echo -e "${RED}✗ Go not installed${NC}"
        return 1
    fi
}

# Function to install missing packages
install_packages() {
    local packages=("$@")
    echo -e "${YELLOW}[!] Installing missing packages: ${packages[*]}${NC}"
    sudo apt update && sudo apt install -y "${packages[@]}"
}

# Check system requirements
echo -e "${BLUE}[*] Checking system requirements...${NC}"

MISSING_PACKAGES=()
CRACKING_TOOLS=()

# Essential packages
if ! command_exists git; then
    echo -e "${RED}✗ git${NC}"
    MISSING_PACKAGES+=("git")
else
    echo -e "${GREEN}✓ git${NC}"
fi

if ! command_exists curl; then
    echo -e "${RED}✗ curl${NC}"
    MISSING_PACKAGES+=("curl")
else
    echo -e "${GREEN}✓ curl${NC}"
fi

if ! command_exists jq; then
    echo -e "${RED}✗ jq${NC}"
    MISSING_PACKAGES+=("jq")
else
    echo -e "${GREEN}✓ jq${NC}"
fi

if ! command_exists make; then
    echo -e "${RED}✗ make${NC}"
    MISSING_PACKAGES+=("build-essential")
else
    echo -e "${GREEN}✓ make${NC}"
fi

# Go language
if ! check_go_version; then
    MISSING_PACKAGES+=("golang-go")
fi

# Optional cracking tools
if ! command_exists hashcat; then
    echo -e "${YELLOW}! hashcat (optional for cracking)${NC}"
    CRACKING_TOOLS+=("hashcat")
else
    echo -e "${GREEN}✓ hashcat${NC}"
fi

if ! command_exists john; then
    echo -e "${YELLOW}! john (optional for cracking)${NC}"
    CRACKING_TOOLS+=("john")
else
    echo -e "${GREEN}✓ john${NC}"
fi

# LDAP utilities
if ! command_exists ldapsearch; then
    echo -e "${YELLOW}! ldap-utils (optional for live scanning)${NC}"
    CRACKING_TOOLS+=("ldap-utils")
else
    echo -e "${GREEN}✓ ldap-utils${NC}"
fi

# Wordlists
if [[ -f "/usr/share/wordlists/rockyou.txt" ]] || [[ -f "/usr/share/wordlists/rockyou.txt.gz" ]]; then
    echo -e "${GREEN}✓ wordlists${NC}"
else
    echo -e "${YELLOW}! wordlists (optional for cracking)${NC}"
    CRACKING_TOOLS+=("wordlists")
fi

echo ""

# Install missing essential packages
if [[ ${#MISSING_PACKAGES[@]} -gt 0 ]]; then
    echo -e "${RED}[!] Missing essential packages detected${NC}"
    read -p "Install missing packages? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        install_packages "${MISSING_PACKAGES[@]}"
    else
        echo -e "${RED}[!] Cannot proceed without essential packages${NC}"
        exit 1
    fi
fi

# Install optional cracking tools
if [[ ${#CRACKING_TOOLS[@]} -gt 0 ]]; then
    echo -e "${YELLOW}[?] Optional packages available for enhanced functionality${NC}"
    echo -e "${YELLOW}    These enable hash cracking and live LDAP scanning${NC}"
    read -p "Install optional packages? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        install_packages "${CRACKING_TOOLS[@]}"
    fi
fi

echo ""
echo -e "${GREEN}[+] Dependency check complete!${NC}"

# Build the project
if [[ -f "go.mod" ]]; then
    echo -e "${BLUE}[*] Building KERB-SLEUTH...${NC}"
    go mod download
    go build -o kerb-sleuth ./cmd/kerb-sleuth
    chmod +x kerb-sleuth
    echo -e "${GREEN}[+] Build successful!${NC}"
    
    # Test the build
    echo -e "${BLUE}[*] Testing build...${NC}"
    if ./kerb-sleuth version > /dev/null 2>&1; then
        echo -e "${GREEN}[+] Binary test successful!${NC}"
    else
        echo -e "${RED}[!] Binary test failed${NC}"
    fi
else
    echo -e "${YELLOW}[!] go.mod not found. Make sure you're in the project directory.${NC}"
fi
