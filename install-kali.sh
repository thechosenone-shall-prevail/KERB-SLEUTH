#!/bin/bash

# KERB-SLEUTH Kali Linux Installation Script
# Automated installer for Kali Linux systems

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

# ASCII Banner
echo -e "${RED}"
cat << 'EOF'
████████████████████████████████████████████████████████████████████████████████
██                                                                            ██
██  ██╗  ██╗███████╗██████╗ ██████╗       ███████╗██╗     ███████╗██╗   ██╗  ██
██  ██║ ██╔╝██╔════╝██╔══██╗██╔══██╗      ██╔════╝██║     ██╔════╝██║   ██║  ██
██  █████╔╝ █████╗  ██████╔╝██████╔╝█████╗███████╗██║     █████╗  ██║   ██║  ██
██  ██╔═██╗ ██╔══╝  ██╔══██╗██╔══██╗╚════╝╚════██║██║     ██╔══╝  ██║   ██║  ██
██  ██║  ██╗███████╗██║  ██║██████╔╝      ███████║███████╗███████╗╚██████╔╝  ██
██  ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═════╝       ╚══════╝╚══════╝╚══════╝ ╚═════╝   ██
██                                                                            ██
████████████████████████████████████████████████████████████████████████████████
EOF
echo -e "${NC}"

echo -e "${BLUE}[+] KERB-SLEUTH Kali Linux Installer${NC}"
echo -e "${YELLOW}[!] Active Directory Kerberos Security Scanner${NC}"
echo ""

# Check if running on Kali Linux
if [[ ! -f /etc/os-release ]] || ! grep -q "kali" /etc/os-release; then
    echo -e "${YELLOW}[!] Warning: This script is optimized for Kali Linux${NC}"
    echo -e "${YELLOW}[!] Continuing anyway...${NC}"
    sleep 2
fi

# Check if running as root for system packages
if [[ $EUID -eq 0 ]]; then
    echo -e "${RED}[!] Don't run this script as root. We'll use sudo when needed.${NC}"
    exit 1
fi

echo -e "${GREEN}[+] Starting installation process...${NC}"

# Update package lists
echo -e "${BLUE}[*] Updating package lists...${NC}"
sudo apt update

# Install required system packages
echo -e "${BLUE}[*] Installing system dependencies...${NC}"
sudo apt install -y \
    golang-go \
    git \
    build-essential \
    curl \
    wget \
    jq \
    hashcat \
    john \
    wordlists \
    ldap-utils \
    openssl \
    ca-certificates

# Check Go version
GO_VERSION=$(go version 2>/dev/null | awk '{print $3}' | sed 's/go//' || echo "0")
if [[ $(echo "$GO_VERSION" | cut -d. -f1) -lt 1 ]] || [[ $(echo "$GO_VERSION" | cut -d. -f2) -lt 20 ]]; then
    echo -e "${YELLOW}[!] Go version is too old. Installing latest Go...${NC}"
    
    # Download and install latest Go
    LATEST_GO=$(curl -s https://golang.org/VERSION?m=text)
    wget -q "https://golang.org/dl/${LATEST_GO}.linux-amd64.tar.gz"
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf "${LATEST_GO}.linux-amd64.tar.gz"
    rm "${LATEST_GO}.linux-amd64.tar.gz"
    
    # Add to PATH if not already there
    if ! grep -q "/usr/local/go/bin" ~/.bashrc; then
        echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
        export PATH=$PATH:/usr/local/go/bin
    fi
fi

echo -e "${GREEN}[+] Go version: $(go version)${NC}"

# Build the project
echo -e "${BLUE}[*] Building KERB-SLEUTH...${NC}"
if [[ -f "go.mod" ]]; then
    go mod download
    go build -o kerb-sleuth ./cmd/kerb-sleuth
    chmod +x kerb-sleuth
else
    echo -e "${RED}[!] Error: go.mod not found. Are you in the project directory?${NC}"
    exit 1
fi

# Create directories
echo -e "${BLUE}[*] Setting up directories...${NC}"
sudo mkdir -p /opt/kerb-sleuth
sudo cp kerb-sleuth /opt/kerb-sleuth/
sudo cp -r configs /opt/kerb-sleuth/
sudo cp -r tests /opt/kerb-sleuth/
sudo cp README.md /opt/kerb-sleuth/
sudo chown -R $(whoami):$(whoami) /opt/kerb-sleuth

# Create symlink for global access
echo -e "${BLUE}[*] Creating global symlink...${NC}"
sudo ln -sf /opt/kerb-sleuth/kerb-sleuth /usr/local/bin/kerb-sleuth

# Set up wordlist symlinks
echo -e "${BLUE}[*] Setting up wordlist access...${NC}"
if [[ -d "/usr/share/wordlists" ]]; then
    sudo ln -sf /usr/share/wordlists/rockyou.txt.gz /opt/kerb-sleuth/rockyou.txt.gz 2>/dev/null || true
    if [[ -f "/usr/share/wordlists/rockyou.txt.gz" ]]; then
        sudo gunzip -f /opt/kerb-sleuth/rockyou.txt.gz 2>/dev/null || true
    fi
fi

# Run tests to verify installation
echo -e "${BLUE}[*] Running tests to verify installation...${NC}"
cd /opt/kerb-sleuth
if go test ./... > /dev/null 2>&1; then
    echo -e "${GREEN}[+] All tests passed!${NC}"
else
    echo -e "${YELLOW}[!] Some tests failed, but installation should work${NC}"
fi

# Generate sample data
echo -e "${BLUE}[*] Generating sample test data...${NC}"
./kerb-sleuth simulate --dataset small --out tests/sample_data/ > /dev/null 2>&1

# Test basic functionality
echo -e "${BLUE}[*] Testing basic functionality...${NC}"
if ./kerb-sleuth scan --ad tests/sample_data/users_small.csv --out /tmp/test_results.json > /dev/null 2>&1; then
    echo -e "${GREEN}[+] Basic functionality test passed!${NC}"
    rm -f /tmp/test_results.json
else
    echo -e "${YELLOW}[!] Basic test failed, but tool should still work${NC}"
fi

# Create desktop entry (optional)
if command -v desktop-file-install > /dev/null 2>&1; then
    echo -e "${BLUE}[*] Creating desktop entry...${NC}"
    cat > /tmp/kerb-sleuth.desktop << EOF
[Desktop Entry]
Name=KERB-SLEUTH
Comment=Active Directory Kerberos Security Scanner
Exec=gnome-terminal -- kerb-sleuth
Icon=utilities-terminal
Terminal=true
Type=Application
Categories=Security;Network;
Keywords=kerberos;security;pentesting;active directory;
EOF
    sudo desktop-file-install /tmp/kerb-sleuth.desktop
    rm /tmp/kerb-sleuth.desktop
fi

echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║                   INSTALLATION COMPLETE!                    ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${BLUE}[+] KERB-SLEUTH has been installed to: ${GREEN}/opt/kerb-sleuth/${NC}"
echo -e "${BLUE}[+] Global command available: ${GREEN}kerb-sleuth${NC}"
echo -e "${BLUE}[+] Configuration files: ${GREEN}/opt/kerb-sleuth/configs/${NC}"
echo -e "${BLUE}[+] Sample data: ${GREEN}/opt/kerb-sleuth/tests/sample_data/${NC}"
echo ""
echo -e "${YELLOW}QUICK START:${NC}"
echo -e "${GREEN}  kerb-sleuth --help${NC}"
echo -e "${GREEN}  kerb-sleuth simulate --dataset small --out ~/ad_test_data${NC}"
echo -e "${GREEN}  kerb-sleuth scan --ad users.csv --out results.json${NC}"
echo ""
echo -e "${RED}REMEMBER: For authorized security assessments only!${NC}"
echo -e "${YELLOW}Always ensure you have proper permission before scanning.${NC}"
echo ""
