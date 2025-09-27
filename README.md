```
██╗  ██╗███████╗██████╗ ██████╗       ███████╗██╗     ███████╗██╗   ██╗████████╗██╗  ██╗
██║ ██╔╝██╔════╝██╔══██╗██╔══██╗      ██╔════╝██║     ██╔════╝██║   ██║╚══██╔══╝██║  ██║
█████╔╝ █████╗  ██████╔╝██████╔╝█████╗███████╗██║     █████╗  ██║   ██║   ██║   ███████║
██╔═██╗ ██╔══╝  ██╔══██╗██╔══██╗╚════╝╚════██║██║     ██╔══╝  ██║   ██║   ██║   ██╔══██║
██║  ██╗███████╗██║  ██║██████╔╝      ███████║███████╗███████╗╚██████╔╝   ██║   ██║  ██║
╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═════╝       ╚══════╝╚══════╝╚══════╝ ╚═════╝    ╚═╝   ╚═╝  ╚═╝
```

<div align="center">

# 🔥 KERB-SLEUTH 🔥
### **Active Directory Kerberos Security Scanner**

[![GitHub license](https://img.shields.io/github/license/thechosenone-shall-prevail/KERB-SLEUTH?style=for-the-badge&color=darkred)](https://github.com/thechosenone-shall-prevail/KERB-SLEUTH/blob/main/LICENSE)
[![GitHub stars](https://img.shields.io/github/stars/thechosenone-shall-prevail/KERB-SLEUTH?style=for-the-badge&color=red)](https://github.com/thechosenone-shall-prevail/KERB-SLEUTH/stargazers)
[![Go version](https://img.shields.io/badge/Go-1.21+-00ADD8?style=for-the-badge&logo=go)](https://golang.org/)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey?style=for-the-badge)](https://github.com/thechosenone-shall-prevail/KERB-SLEUTH/releases)

**🩸 BLEEDING WINDOWS AUTHENTICATION 🩸**

*A production-ready, single-binary Go tool for identifying AS-REP and Kerberoastable targets in Active Directory environments. Designed for offline-first operation with safe-by-default behavior.*

</div>

---

## ⚠️ **LEGAL DISCLAIMER** ⚠️

```diff
+ This tool is for AUTHORIZED security assessments ONLY!
+ Unauthorized access to computer systems is ILLEGAL and punishable by law.
+ Always ensure you have explicit written permission before using this tool.
+ The authors assume NO LIABILITY for misuse or damage caused by this program.
```

---

## 🎯 **FEATURES**

### 🔍 **Core Capabilities**
- 🛡️ **AS-REP Roasting Detection** - Identifies accounts with pre-authentication disabled
- ⚡ **Kerberoasting Detection** - Finds accounts with Service Principal Names (SPNs)
- 📊 **Intelligent Scoring System** - Configurable heuristics for risk assessment
- 🎨 **Beautiful ASCII Banners** - Random bloody Windows logo displays (msfconsole style)

### 💾 **Data Processing**
- 📁 **Multiple Input Formats** - CSV, LDIF, JSON support
- 🌐 **Offline-First Design** - Operates primarily on exported AD data
- 📈 **Smart Parsing** - Handles various AD export formats automatically
- 🔄 **Synthetic Data Generator** - Built-in test data creation

### 📤 **Output Formats**
- 📋 **JSON Reports** - Detailed results with scoring and reasons
- 📊 **CSV Summaries** - Simplified tabular format for reporting
- 🚨 **Sigma Rules** - Generated detection rules for SIEM integration
- 🔓 **Hash Export** - Optional hash extraction for authorized cracking

### 🛡️ **Security Features**
- 🔒 **Safe by Default** - Requires explicit authorization for sensitive operations
- 📝 **Comprehensive Logging** - Detailed audit trails
- ⚡ **Single Binary** - Easy deployment with minimal dependencies
- 🎯 **Production Ready** - Robust error handling and validation

---

## 🚀 **INSTALLATION**

### 📦 **Pre-built Binaries**
```bash
# Download from releases
wget https://github.com/thechosenone-shall-prevail/KERB-SLEUTH/releases/latest/download/kerb-sleuth-linux-amd64
chmod +x kerb-sleuth-linux-amd64
./kerb-sleuth-linux-amd64 --help
```

### 🔨 **Build from Source**
```bash
git clone https://github.com/thechosenone-shall-prevail/KERB-SLEUTH.git
cd KERB-SLEUTH
make build
```

### 🏁 **Kali Linux (Automated)**
```bash
# One-liner install
curl -sSL https://raw.githubusercontent.com/thechosenone-shall-prevail/KERB-SLEUTH/main/quick-install.sh | bash

# Full installation with dependencies
git clone https://github.com/thechosenone-shall-prevail/KERB-SLEUTH.git
cd KERB-SLEUTH
chmod +x install-kali.sh
./install-kali.sh
```

### 🐳 **Docker**
```bash
# Build and run with Docker
git clone https://github.com/thechosenone-shall-prevail/KERB-SLEUTH.git
cd KERB-SLEUTH
./install-docker.sh

# Quick run
./run-docker.sh scan --ad /data/users.csv

# Shell access
./docker-shell.sh

# Docker Compose
docker-compose up -d
docker-compose exec kerb-sleuth ./kerb-sleuth --help
```

---

## ⚡ **QUICK START**

### 1️⃣ **Export AD Data**
```powershell
# PowerShell - Export all users with properties
Get-ADUser -Filter * -Properties * | Export-Csv users.csv -NoTypeInformation

# Alternative: LDIF export
ldifde -f users.ldif -d "DC=corp,DC=local" -r "(objectClass=user)"
```

### 2️⃣ **Run Kerb-Sleuth**
```bash
# Basic scan
./kerb-sleuth scan --ad users.csv --out results.json

# Advanced scan with all outputs
./kerb-sleuth scan --ad users.csv --out results.json --csv --siem --crack --i-am-authorized
```

### 3️⃣ **Analyze Results**
```bash
# View summary
cat results.json | jq '.summary'

# High-risk targets only
cat results.json | jq '.candidates[] | select(.score >= 80)'
```

---

## 🎮 **USAGE EXAMPLES**

### 🔍 **Basic Operations**
```bash
# Scan AD export
kerb-sleuth scan --ad users.csv --out results.json

# Generate test data
kerb-sleuth simulate --dataset small --out tests/sample_data/

# Multiple output formats
kerb-sleuth scan --ad users.csv --csv --siem --out comprehensive_scan
```

### 🔓 **Advanced Operations (Authorized Only)**
```bash
# Hash export for cracking
kerb-sleuth scan --ad users.csv --crack --wordlist rockyou.txt --i-am-authorized

# Live LDAP scan
kerb-sleuth live-scan --ldap ldaps://dc.corp.local --bind-user scanner --bind-pass 'P@ssw0rd' --i-am-authorized
```

### ⚙️ **Custom Configuration**
```bash
# Custom scoring weights
kerb-sleuth scan --ad users.csv --config custom-weights.yml --out targeted_results.json
```

---

## 📊 **OUTPUT FORMATS**

### 📋 **JSON Output**
```json
{
  "summary": {
    "total_users": 1337,
    "asrep_candidates": 13,
    "kerberoast_candidates": 42,
    "high_risk": 7,
    "medium_risk": 23,
    "low_risk": 25
  },
  "candidates": [
    {
      "sam": "backup_svc",
      "type": "ASREP",
      "score": 95,
      "severity": "High",
      "reasons": [
        "DoesNotRequirePreAuth enabled",
        "Password older than 365 days",
        "Member of Domain Admins",
        "Never logged in"
      ],
      "spns": [],
      "pwd_last_set": "2022-01-15T10:30:00Z",
      "member_of": ["CN=Domain Admins,CN=Users,DC=corp,DC=local"],
      "suggested_action": "Disable account or enable pre-authentication"
    },
    {
      "sam": "sql_service",
      "type": "KERBEROAST", 
      "score": 87,
      "severity": "High",
      "reasons": [
        "Multiple SPNs registered",
        "Password older than 180 days",
        "High-value service account"
      ],
      "spns": [
        "MSSQLSvc/sql01.corp.local:1433",
        "MSSQLSvc/sql01.corp.local"
      ],
      "export_hash_path": "exports/kerb_hashes.txt",
      "suggested_action": "Implement Managed Service Accounts (MSA)"
    }
  ]
}
```

### 📈 **CSV Summary**
```csv
SamAccountName,Type,Score,Severity,Reasons,SPNs,ExportHashPath
backup_svc,ASREP,95,High,"DoesNotRequirePreAuth enabled; Password older than 365 days",,
sql_service,KERBEROAST,87,High,"Multiple SPNs registered; Password older than 180 days","MSSQLSvc/sql01.corp.local:1433",exports/kerb_hashes.txt
```

### 🚨 **Sigma Detection Rules**
```yaml
title: AS-REP Roasting Detection
description: Detects potential AS-REP roasting attempts
status: experimental
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4768
    PreAuthType: 0
  condition: selection
level: high
```

---

## ⚙️ **CONFIGURATION**

### 📝 **Custom Scoring Weights** (`configs/defaults.yml`)
```yaml
weights:
  # AS-REP Roasting Weights
  asrep_base: 50
  asrep_preauth: 30
  asrep_pwd_old: 20
  asrep_admin_group: 25
  asrep_never_login: 15
  asrep_disabled_penalty: -50
  
  # Kerberoasting Weights  
  kerberoast_base: 40
  kerberoast_spn: 25
  kerberoast_multiple_spns: 15
  kerberoast_pwd_old: 20
  kerberoast_high_value: 30

thresholds:
  high: 85
  medium: 60
  low: 30

time:
  pwd_old_days: 90
  pwd_very_old_days: 365
  never_login_days: 30

admin_groups:
  - "CN=Domain Admins"
  - "CN=Enterprise Admins"
  - "CN=Schema Admins"
  - "CN=Administrators"
  - "CN=Backup Operators"

high_value_services:
  - "MSSQLSvc"
  - "HTTP"
  - "LDAP"
  - "CIFS"
  - "HOST"
```

---

## 🛠️ **DEVELOPMENT**

### 🧪 **Running Tests**
```bash
# Run all tests
make test

# Run with coverage
make test-coverage

# Run specific package tests
go test ./pkg/ingest -v
```

### 🏗️ **Building for Multiple Platforms**
```bash
# Build for all platforms
make build-all

# Specific platform builds
make build-linux
make build-windows
make build-mac
```

### 📦 **Docker Development**
```bash
# Build docker image
make docker-build

# Run in container
make docker-run
```

### 🚀 **Release Preparation**
```bash
# Automated release preparation
./prepare-release.sh

# Manual steps:
# 1. Update version in go.mod
# 2. Run tests: make test
# 3. Build binaries: make build-all
# 4. Create git tag: git tag v1.0.0
# 5. Push to GitHub: git push origin v1.0.0
# 6. Create GitHub release with binaries
```

---

## 🎨 **BANNER GALLERY**

Kerb-Sleuth features multiple random ASCII art banners that display on startup, similar to Metasploit's msfconsole:

- 🩸 **Bleeding Windows Logo** - Realistic Windows logo with blood dripping effects
- 💀 **Skull & Crossbones** - Classic hacker aesthetic with blood-red styling  
- 🌀 **Matrix Style** - Green matrix rain with Kerberos branding
- 🔥 **Cyber Aesthetic** - Modern cyberpunk design with neon colors
- ⚡ **Minimalist Hacker** - Clean, professional penetration testing look

---

## 🤝 **CONTRIBUTING**

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### 🔒 **Security Policy**
- All contributions must follow security-first principles
- No real credentials or sensitive data in code
- Synthetic test data only
- All destructive operations require explicit authorization

### 🐛 **Bug Reports**
Found a bug? Please open an issue with:
- Operating system and Go version
- Command that caused the issue
- Expected vs actual behavior
- Sample data (anonymized)

---

## 📋 **ROADMAP**

### 🚀 **Version 2.0**
- [ ] Live Active Directory integration
- [ ] Real-time monitoring capabilities
- [ ] Advanced machine learning scoring
- [ ] Web dashboard interface
- [ ] Kubernetes deployment

### 🔮 **Future Features**
- [ ] BloodHound integration
- [ ] Azure AD support
- [ ] Custom plugin system
- [ ] Distributed scanning
- [ ] Mobile app companion

---

## 📊 **STATISTICS**

```
Lines of Code: ~2,500
Test Coverage: >85%
Supported Formats: CSV, LDIF, JSON
Output Formats: JSON, CSV, Sigma Rules
Platforms: Windows, Linux, macOS, ARM64
```

---

## 🏆 **HALL OF FAME**

### 🎖️ **Contributors**
- **@thechosenone-shall-prevail** - Project Creator & Lead Developer

### 🙏 **Special Thanks**
- Active Directory community for testing and feedback
- Go security community for best practices
- Red team operators for real-world validation

---

## 📞 **SUPPORT**

- 📚 **Documentation**: Check the [Wiki](https://github.com/thechosenone-shall-prevail/KERB-SLEUTH/wiki)
- 💬 **Discussions**: [GitHub Discussions](https://github.com/thechosenone-shall-prevail/KERB-SLEUTH/discussions)  
- 🐛 **Issues**: [Bug Reports](https://github.com/thechosenone-shall-prevail/KERB-SLEUTH/issues)
- 📧 **Email**: security@[domain] (for security issues only)

---

## 📜 **LICENSE**

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

---

<div align="center">

### 🔥 **REMEMBER: WITH GREAT POWER COMES GREAT RESPONSIBILITY** 🔥

**Use this tool ethically and legally. Always obtain proper authorization.**

---

*Made with ❤️ and ☕ by [@thechosenone-shall-prevail](https://github.com/thechosenone-shall-prevail)*

**⭐ Star this repo if you find it useful! ⭐**

</div>
