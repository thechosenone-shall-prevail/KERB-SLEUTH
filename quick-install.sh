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

echo -e "${GREEN}[+] Quick installation complete!${NC}"
echo -e "${YELLOW}[!] Run 'kerb-sleuth --help' to get started${NC}"
