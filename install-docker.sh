#!/bin/bash

# KERB-SLEUTH Docker Installation Script
# Builds and sets up KERB-SLEUTH in Docker containers

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Banner
echo -e "${RED}"
cat << 'EOF'
██╗  ██╗███████╗██████╗ ██████╗       ███████╗██╗     ███████╗██╗   ██╗████████╗██╗  ██╗
██║ ██╔╝██╔════╝██╔══██╗██╔══██╗      ██╔════╝██║     ██╔════╝██║   ██║╚══██╔══╝██║  ██║
█████╔╝ █████╗  ██████╔╝██████╔╝█████╗███████╗██║     █████╗  ██║   ██║   ██║   ███████║
██╔═██╗ ██╔══╝  ██╔══██╗██╔══██╗╚════╝╚════██║██║     ██╔══╝  ██║   ██║   ██║   ██╔══██║
██║  ██╗███████╗██║  ██║██████╔╝      ███████║███████╗███████╗╚██████╔╝   ██║   ██║  ██║
╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═════╝       ╚══════╝╚══════╝╚══════╝ ╚═════╝    ╚═╝   ╚═╝  ╚═╝
                                         DOCKER INSTALLER
EOF
echo -e "${NC}"

echo -e "${BLUE}[*] KERB-SLEUTH Docker Installation${NC}"
echo ""

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo -e "${RED}[!] Docker is not installed. Please install Docker first.${NC}"
    echo -e "${YELLOW}    On Kali Linux: sudo apt update && sudo apt install docker.io${NC}"
    exit 1
fi

# Check if Docker Compose is available
if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
    echo -e "${RED}[!] Docker Compose is not available. Please install Docker Compose.${NC}"
    echo -e "${YELLOW}    On Kali Linux: sudo apt install docker-compose${NC}"
    exit 1
fi

echo -e "${GREEN}[+] Docker is available${NC}"

# Create necessary directories
echo -e "${BLUE}[*] Creating directories...${NC}"
mkdir -p data results

# Build the Docker image
echo -e "${BLUE}[*] Building KERB-SLEUTH Docker image...${NC}"
docker build -t kerb-sleuth:latest .

echo -e "${GREEN}[+] Docker image built successfully!${NC}"

# Create convenience scripts
echo -e "${BLUE}[*] Creating convenience scripts...${NC}"

# Create run-docker.sh
cat > run-docker.sh << 'SCRIPT'
#!/bin/bash
# Quick run script for KERB-SLEUTH in Docker

if [ $# -eq 0 ]; then
    echo "Usage: ./run-docker.sh [kerb-sleuth arguments]"
    echo "Example: ./run-docker.sh analyze /data/tickets.kirbi"
    echo "Example: ./run-docker.sh --help"
    exit 1
fi

docker run --rm -it \
    -v "$(pwd)/data:/data" \
    -v "$(pwd)/results:/home/sleuth/results" \
    kerb-sleuth:latest "$@"
SCRIPT

# Create shell access script
cat > docker-shell.sh << 'SCRIPT'
#!/bin/bash
# Get shell access to KERB-SLEUTH container

docker run --rm -it \
    -v "$(pwd)/data:/data" \
    -v "$(pwd)/results:/home/sleuth/results" \
    --entrypoint /bin/sh \
    kerb-sleuth:latest
SCRIPT

chmod +x run-docker.sh docker-shell.sh

echo -e "${GREEN}[+] Created convenience scripts:${NC}"
echo -e "  ${YELLOW}run-docker.sh${NC}   - Run KERB-SLEUTH commands in Docker"
echo -e "  ${YELLOW}docker-shell.sh${NC} - Get shell access to container"

# Show usage examples
echo ""
echo -e "${GREEN}[+] Installation complete!${NC}"
echo ""
echo -e "${BLUE}Usage Examples:${NC}"
echo -e "  ${YELLOW}./run-docker.sh --help${NC}"
echo -e "  ${YELLOW}./run-docker.sh analyze /data/tickets.kirbi${NC}"
echo -e "  ${YELLOW}./run-docker.sh simulate --dataset large${NC}"
echo -e "  ${YELLOW}./docker-shell.sh${NC}"
echo ""
echo -e "${BLUE}Docker Compose (for persistent container):${NC}"
echo -e "  ${YELLOW}docker-compose up -d${NC}"
echo -e "  ${YELLOW}docker-compose exec kerb-sleuth ./kerb-sleuth --help${NC}"
echo -e "  ${YELLOW}docker-compose down${NC}"
echo ""
echo -e "${BLUE}Development mode:${NC}"
echo -e "  ${YELLOW}docker-compose --profile dev up -d kerb-sleuth-dev${NC}"
echo -e "  ${YELLOW}docker-compose exec kerb-sleuth-dev sh${NC}"
echo ""
echo -e "Place your Kerberos files in the ${YELLOW}data/${NC} directory"
echo -e "Results will be saved to the ${YELLOW}results/${NC} directory"
