#!/bin/bash

# Quick Install Script for KERB-SLEUTH
# One-liner installation for Kali Linux

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${RED}🔥 KERB-SLEUTH Quick Installer 🔥${NC}"
echo ""

# Clone repository
echo -e "${BLUE}[*] Cloning KERB-SLEUTH repository...${NC}"
if [[ -d "KERB-SLEUTH" ]]; then
    cd KERB-SLEUTH
    git pull
else
    git clone https://github.com/thechosenone-shall-prevail/KERB-SLEUTH.git
    cd KERB-SLEUTH
fi

# Make installer executable and run
chmod +x install-kali.sh
./install-kali.sh

# --- Build the Go binary for kerb-sleuth ---
echo -e "${BLUE}[*] Building kerb-sleuth binary...${NC}"
BIN_TARGET="$HOME/.local/bin"
mkdir -p "$BIN_TARGET"

# Detect cmd folder containing main package
if [ -d "cmd/kerb-sleuth" ]; then
    go build -o "$BIN_TARGET/kerb-sleuth" ./cmd/kerb-sleuth
    chmod +x "$BIN_TARGET/kerb-sleuth"
else
    echo -e "${RED}[!] Could not find cmd/kerb-sleuth to build${NC}"
fi

# Ensure ~/.local/bin is on PATH
if ! echo "$PATH" | grep -q "$HOME/.local/bin"; then
    echo 'export PATH=$HOME/.local/bin:$PATH' >> "$HOME/.bashrc"
    echo -e "${YELLOW}[*] Added ~/.local/bin to PATH. Run 'source ~/.bashrc' or open a new shell.${NC}"
fi

echo -e "${GREEN}[+] Quick installation complete!${NC}"
echo -e "${YELLOW}[!] Run 'kerb-sleuth --help' to get started${NC}"
