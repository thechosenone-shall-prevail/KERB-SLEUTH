#!/bin/bash

# KERB-SLEUTH Release Preparation Script
# Prepares the project for GitHub release with proper versioning and builds

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m'

# Release banner
echo -e "${PURPLE}"
cat << 'EOF'
██████╗ ███████╗██╗     ███████╗ █████╗ ███████╗███████╗    ██████╗ ██████╗ ███████╗██████╗ 
██╔══██╗██╔════╝██║     ██╔════╝██╔══██╗██╔════╝██╔════╝    ██╔══██╗██╔══██╗██╔════╝██╔══██╗
██████╔╝█████╗  ██║     █████╗  ███████║███████╗█████╗      ██████╔╝██████╔╝█████╗  ██████╔╝
██╔══██╗██╔══╝  ██║     ██╔══╝  ██╔══██║╚════██║██╔══╝      ██╔═══╝ ██╔══██╗██╔══╝  ██╔═══╝ 
██║  ██║███████╗███████╗███████╗██║  ██║███████║███████╗    ██║     ██║  ██║███████╗██║     
╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝    ╚═╝     ╚═╝  ╚═╝╚══════╝╚═╝     
                                  KERB-SLEUTH RELEASE PREP
EOF
echo -e "${NC}"

# Function to prompt for user input
prompt_user() {
    local prompt="$1"
    local default="$2"
    local result
    
    if [[ -n "$default" ]]; then
        read -p "$prompt [$default]: " result
        result="${result:-$default}"
    else
        read -p "$prompt: " result
    fi
    
    echo "$result"
}

# Check if we're in a git repository
if ! git rev-parse --git-dir > /dev/null 2>&1; then
    echo -e "${RED}[!] Error: Not in a git repository${NC}"
    exit 1
fi

# Check if we're on main branch
CURRENT_BRANCH=$(git branch --show-current)
if [[ "$CURRENT_BRANCH" != "main" ]]; then
    echo -e "${YELLOW}[!] Warning: You're on branch '$CURRENT_BRANCH', not 'main'${NC}"
    if ! prompt_user "Continue anyway? (y/N)" "n" | grep -qi "^y"; then
        exit 1
    fi
fi

# Check for uncommitted changes
if ! git diff-index --quiet HEAD --; then
    echo -e "${RED}[!] Error: You have uncommitted changes${NC}"
    echo -e "${YELLOW}    Please commit or stash your changes first${NC}"
    exit 1
fi

echo -e "${BLUE}[*] Preparing KERB-SLEUTH for release...${NC}"
echo ""

# Get current version from git tags
CURRENT_VERSION=$(git describe --tags --abbrev=0 2>/dev/null || echo "v0.0.0")
echo -e "${BLUE}[*] Current version: $CURRENT_VERSION${NC}"

# Prompt for new version
NEW_VERSION=$(prompt_user "Enter new version (e.g., v1.0.0)" "")
if [[ -z "$NEW_VERSION" ]]; then
    echo -e "${RED}[!] Version cannot be empty${NC}"
    exit 1
fi

# Validate version format
if [[ ! "$NEW_VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9]+)?$ ]]; then
    echo -e "${RED}[!] Invalid version format. Use vX.Y.Z or vX.Y.Z-suffix${NC}"
    exit 1
fi

# Update version in go.mod if needed
if [[ -f "go.mod" ]]; then
    echo -e "${BLUE}[*] Updating go.mod version...${NC}"
    # This is more for documentation; Go modules use git tags for versioning
fi

# Run tests
echo -e "${BLUE}[*] Running tests...${NC}"
if ! go test -v ./...; then
    echo -e "${RED}[!] Tests failed. Please fix them before releasing.${NC}"
    exit 1
fi
echo -e "${GREEN}[+] All tests passed${NC}"

# Run go vet
echo -e "${BLUE}[*] Running go vet...${NC}"
if ! go vet ./...; then
    echo -e "${RED}[!] go vet found issues. Please fix them before releasing.${NC}"
    exit 1
fi
echo -e "${GREEN}[+] go vet passed${NC}"

# Clean previous builds
echo -e "${BLUE}[*] Cleaning previous builds...${NC}"
rm -rf dist/
mkdir -p dist

# Build for multiple platforms
echo -e "${BLUE}[*] Building release binaries...${NC}"

PLATFORMS=(
    "linux/amd64"
    "linux/arm64" 
    "darwin/amd64"
    "darwin/arm64"
    "windows/amd64"
)

for PLATFORM in "${PLATFORMS[@]}"; do
    GOOS=${PLATFORM%/*}
    GOARCH=${PLATFORM#*/}
    
    echo -e "${YELLOW}  Building for $GOOS/$GOARCH...${NC}"
    
    BINARY_NAME="kerb-sleuth"
    if [[ "$GOOS" == "windows" ]]; then
        BINARY_NAME="kerb-sleuth.exe"
    fi
    
    OUTPUT_DIR="dist/kerb-sleuth-$NEW_VERSION-$GOOS-$GOARCH"
    mkdir -p "$OUTPUT_DIR"
    
    # Build binary
    env GOOS="$GOOS" GOARCH="$GOARCH" go build -ldflags "-s -w -X main.version=$NEW_VERSION" -o "$OUTPUT_DIR/$BINARY_NAME" ./cmd/kerb-sleuth
    
    # Copy additional files
    cp README.md "$OUTPUT_DIR/"
    cp LICENSE "$OUTPUT_DIR/"
    cp -r configs "$OUTPUT_DIR/"
    cp -r tests/sample_data "$OUTPUT_DIR/sample_data"
    
    # Create archive
    if [[ "$GOOS" == "windows" ]]; then
        (cd dist && zip -r "kerb-sleuth-$NEW_VERSION-$GOOS-$GOARCH.zip" "kerb-sleuth-$NEW_VERSION-$GOOS-$GOARCH/")
    else
        (cd dist && tar -czf "kerb-sleuth-$NEW_VERSION-$GOOS-$GOARCH.tar.gz" "kerb-sleuth-$NEW_VERSION-$GOOS-$GOARCH/")
    fi
done

echo -e "${GREEN}[+] All binaries built successfully${NC}"

# Create checksums
echo -e "${BLUE}[*] Creating checksums...${NC}"
(cd dist && find . -name "*.tar.gz" -o -name "*.zip" | xargs sha256sum > checksums.txt)

# Create release notes template
echo -e "${BLUE}[*] Creating release notes template...${NC}"
cat > "RELEASE_NOTES_$NEW_VERSION.md" << EOF
# KERB-SLEUTH $NEW_VERSION Release Notes

## 🎯 Overview
Brief description of this release...

## ✨ New Features
- Feature 1
- Feature 2

## 🐛 Bug Fixes
- Fix 1
- Fix 2

## 🔧 Improvements
- Improvement 1
- Improvement 2

## 📦 Installation

### Quick Install (Kali Linux)
\`\`\`bash
curl -sSL https://raw.githubusercontent.com/YourUsername/KERB-SLEUTH/main/quick-install.sh | bash
\`\`\`

### Manual Download
Download the appropriate binary for your platform from the assets below.

### Docker
\`\`\`bash
git clone https://github.com/YourUsername/KERB-SLEUTH.git
cd KERB-SLEUTH
./install-docker.sh
\`\`\`

## 🔍 Usage
\`\`\`bash
kerb-sleuth --help
kerb-sleuth analyze /path/to/tickets.kirbi
kerb-sleuth simulate --dataset large
\`\`\`

## 📊 Checksums
See \`checksums.txt\` for file verification.

---
**Full Changelog**: https://github.com/YourUsername/KERB-SLEUTH/compare/PREVIOUS_TAG...$NEW_VERSION
EOF

# Commit and tag
echo -e "${BLUE}[*] Creating git tag...${NC}"
git add -A
if ! git diff --cached --quiet; then
    git commit -m "chore: prepare release $NEW_VERSION"
fi

git tag -a "$NEW_VERSION" -m "Release $NEW_VERSION"

echo -e "${GREEN}[+] Release preparation complete!${NC}"
echo ""
echo -e "${BLUE}Next steps:${NC}"
echo -e "  1. Review the release notes in ${YELLOW}RELEASE_NOTES_$NEW_VERSION.md${NC}"
echo -e "  2. Push the tag: ${YELLOW}git push origin $NEW_VERSION${NC}"
echo -e "  3. Push commits: ${YELLOW}git push origin main${NC}"
echo -e "  4. GitHub Actions will automatically create the release with binaries"
echo -e "  5. Review and publish the release on GitHub"
echo ""
echo -e "${BLUE}Built files:${NC}"
ls -la dist/
echo ""
echo -e "${GREEN}🎉 KERB-SLEUTH $NEW_VERSION is ready for release!${NC}"
