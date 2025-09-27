#!/bin/bash

# Set executable permissions for all shell scripts
# Run this after cloning the repository

echo "Setting executable permissions for KERB-SLEUTH scripts..."

chmod +x install-kali.sh
chmod +x quick-install.sh
chmod +x check-deps.sh
chmod +x install-docker.sh
chmod +x prepare-release.sh

echo "✅ All scripts are now executable"
echo ""
echo "Available scripts:"
echo "  📦 install-kali.sh     - Full Kali Linux installation"
echo "  ⚡ quick-install.sh    - One-liner installation"
echo "  🔍 check-deps.sh      - Check and install dependencies"
echo "  🐳 install-docker.sh  - Docker setup and installation"
echo "  🚀 prepare-release.sh - Prepare project for GitHub release"
