# Active Directory Kerberos Security Scanner

![GitHub license](https://img.shields.io/github/license/thechosenone-shall-prevail/KERB-SLEUTH) ![GitHub stars](https://img.shields.io/github/stars/thechosenone-shall-prevail/KERB-SLEUTH) ![Go version](https://img.shields.io/github/go-mod/go-version/thechosenone-shall-prevail/KERB-SLEUTH) ![Platform](https://img.shields.io/badge/platform-windows-blue)

🩸 BLEEDING WINDOWS AUTHENTICATION 🩸

A production-ready, single-binary Go tool for identifying AS-REP and Kerberoastable targets in Active Directory environments, combined with deep reconnaissance, automated protocol discovery, and real Kerberos protocol interactions.

## Core Capabilities

- **Identity Reconnaissance**: Automated enumeration of all user objects, including detailed attributes such as descriptions, group memberships (MemberOf), account security flags (UAC), and lastLogonTimestamp.
- **Real Kerberos Protocol**: Multi-etype AS-REP roasting (AES256, AES128, RC4) and authenticated Kerberoasting using real Kerberos protocol interactions.
- **Secure LDAP**: Full TLS support with LDAPS (636), STARTTLS (389), certificate validation, and automatic fallback.
- **Protocol Discovery**: Rapid service checking for Kerberos (88), LDAP (389/636), SMB (445), WinRM (5985/5986), RDP (3389), Global Catalog (3268/3269), and more.
- **Trust & DNS Analysis**: Domain trust enumeration plus DNS zone transfer checks for AD-connected nameservers.
- **LAPS / gMSA Enumeration**: Detect LAPS-managed passwords and managed service accounts in Active Directory.
- **GPO Hardening Analysis**: Enumerate Group Policy containers and flag insecure or non-default policy settings.
- **Session Intelligence**: Infer active account sessions from LDAP logon timestamps and logon counts.
- **ACL / Privilege Analysis**: Identify admin-marked and privileged objects beyond basic RBCD checks.
- **Administrative "Pwned" Detection**: Real-time detection of administrative privileges by attempting access to ADMIN$ and C$ shares.
- **Credential Harvesting**: Automated scanning of SYSVOL for Group Policy Preferences (GPP) XML files, deep LDAP attribute mining, and decryption of `cpassword` attributes.
- **Advanced Attack Vectors**: Built-in support for analyzing RBCD, S4U delegation paths, DCSync replication rights, and PKINIT/AD CS templates.

## Installation

```bash
git clone https://github.com/thechosenone-shall-prevail/KERB-SLEUTH.git
cd KERB-SLEUTH
go build -o kerb-sleuth ./cmd/kerb-sleuth/
```

## Quick Start

### Passive Mode
Use the passive mode for enumeration and discovery only.

```bash
./kerb-sleuth -t 10.129.29.229 -u wallace.everette@logging.htb -p 'Welcome2026@' --mode passive
```

### Aggressive Mode
Use aggressive mode for full AD attack surface discovery and offensive analysis.

```bash
./kerb-sleuth -t 10.129.29.229 -u wallace.everette@logging.htb -p 'Welcome2026@' --mode aggressive
```

### Optional Output
Save additional formats if you want:

```bash
./kerb-sleuth -t 10.129.29.229 -u wallace.everette@logging.htb -p 'Welcome2026@' --mode aggressive -o results.json --csv results.csv --siem
```

## Command-Line Flags

### Primary Options
| Flag | Description |
|------|-------------|
| `-t <target>` | Target IP or hostname (required) |
| `-u <user>` | Username for authentication (supports `DOMAIN\user`, `user@domain.com`) |
| `-p <pass>` | Password for authentication |
| `-d <domain>` | Domain name (auto-detected if omitted) |
| `--mode <passive|aggressive>` | Scan mode; passive is enumeration-only, aggressive runs full analysis |

### Output Options
| Flag | Description |
|------|-------------|
| `-o <file>` | JSON output file (default: `results.json`) |
| `--csv <file>` | Optional CSV output file |
| `--siem` | Generate SIEM detection rules |

### Legacy / Advanced Options
These are available for power users, but not required for normal use.

| Flag | Description |
|------|-------------|
| `--ldaps` | Use LDAPS on port 636 |
| `--starttls` | Use STARTTLS on port 389 |
| `--insecure` | Skip TLS certificate verification |
| `--cafile <path>` | CA certificate bundle for TLS validation |
| `--kdc <host>` | Explicit Kerberos KDC hostname or IP |
| `--fallback-tls` | Try plain LDAP → STARTTLS → LDAPS automatically |
| `-w <wordlist>` | Wordlist for hash cracking (advanced) |
| `--audit` | Audit mode with reduced offensive activity |

## Features in Detail

## Features in Detail

### 🔐 Secure LDAP Connections

KERB-SLEUTH supports multiple LDAP connection modes:

**LDAPS (Port 636):**
```bash
./kerb-sleuth -t dc.corp.local -u admin -p password --ldaps
```

**STARTTLS (Port 389):**
```bash
./kerb-sleuth -t dc.corp.local -u admin -p password --starttls
```

**Certificate Validation:**
```bash
./kerb-sleuth -t dc.corp.local -u admin -p password \
  --ldaps --cafile /etc/ssl/certs/corp-ca.pem
```

**Automatic Fallback:**
```bash
./kerb-sleuth -t dc.corp.local -u admin -p password --fallback-tls
# Tries: Plain LDAP → STARTTLS → LDAPS
```

### 🎯 KDC Resolution

KERB-SLEUTH automatically resolves the Kerberos KDC using multiple methods:

1. **Explicit Override:** `--kdc kdc.corp.local`
2. **RootDSE Attribute:** `dnsHostName` from LDAP RootDSE
3. **LDAP Host:** Uses the LDAP connection target
4. **DNS SRV Lookup:** `_kerberos._tcp.dc._msdcs.<realm>`
5. **DNS SRV Fallback:** `_kerberos._tcp.<realm>`

### 🔑 Real Kerberos Protocol

**Multi-Etype AS-REP Roasting:**
- Supports AES256-CTS-HMAC-SHA1-96, AES128-CTS-HMAC-SHA1-96, and RC4-HMAC
- Automatically formats hashes for hashcat mode 18200

**Authenticated Kerberoasting:**
- Uses bind credentials to obtain TGS tickets
- Supports AES and RC4 encryption types
- Formats hashes for hashcat mode 13100 (RC4) and 19600/19700 (AES)

**Rate Limiting:**
- 120ms delay between hash extractions to avoid detection

### 📊 Protocol Discovery

Automatically scans for active services:
- **88** - Kerberos
- **135** - RPC
- **389** - LDAP
- **445** - SMB
- **464** - kpasswd
- **636** - LDAPS
- **3268** - Global Catalog
- **3269** - Global Catalog SSL
- **3389** - RDP
- **5985** - WinRM
- **5986** - WinRM SSL
- **9389** - Active Directory Web Services

### 🕵️ Advanced Analysis Modules

**RBCD (Resource-Based Constrained Delegation):**
- Enumerates `msDS-AllowedToActOnBehalfOfOtherIdentity` attributes
- Identifies exploitable delegation paths
- Calculates risk scores and provides exploitation guidance

**S4U (Service for User) Delegation:**
- Detects unconstrained and constrained delegation
- Analyzes S4U2Self and S4U2Proxy configurations
- Identifies high-privilege accounts with delegation rights

**DCSync:**
- Scans domain security descriptor for replication extended rights
- Detects `DS-Replication-Get-Changes`, `DS-Replication-Get-Changes-All`, and `DS-Replication-Get-Changes-In-Filtered-Set`
- No full-tree LDAP queries (efficient domain base search only)

**PKINIT/AD CS:**
- Enumerates certificate templates
- Identifies autoenrollment and SmartCardLogon configurations
- Detects excessive enrollment rights

### 🎯 Risk Insights & Attack Paths

KERB-SLEUTH automatically generates tactical attack chains:

```
[CRITICAL] High Value Target: Administrator (Admin Privileges Detected)
[CRITICAL] LOOT FOUND in LDAP Description of svc_backup (Found keyword: 'password')
[HIGH] READ access to juicy share: \\dc\backup (Found 12 sensitive files)
--- Tactical Attack Chain ---
Step 1: Extract credentials from LDAP 'Description' fields.
Step 2: Use harvested credentials to test against SMB, WinRM, and RDP.
Step 3: Target identified Domain Admins for full domain compromise.
```

### 🔓 Credential Harvesting

**LDAP Attribute Mining:**
- Scans `Description`, `Info`, `Comment`, `PhysicalDeliveryOfficeName`, `PostOfficeBox`
- Detects keywords: `password`, `pass:`, `pwd=`, `secret`, `creds`, `token`

**GPP Password Decryption:**
- Scans SYSVOL for `Groups.xml`, `Services.xml`, `Scheduledtasks.xml`, `DataSources.xml`
- Automatically decrypts `cpassword` attributes

**SMB Share Enumeration:**
- Identifies "juicy" shares: `logs`, `backup`, `it`, `hr`, `users`, `shared`
- Deep file hunt for sensitive files: `.config`, `.xml`, `.ini`, `.txt`, `.log`, `.bak`

### 📤 Output Formats

**JSON (Schema Version 2.0):**
```json
{
  "schema_version": "2.0",
  "domain": {
    "name": "CORP.LOCAL",
    "dn": "DC=corp,DC=local",
    "functional_level": "2016",
    "os_version": "Windows Server 2019"
  },
  "summary": {
    "total_users": 1523,
    "asrep_candidates": 12,
    "kerberoast_candidates": 34,
    "high_risk_objects": 46
  },
  "candidates": [...],
  "risk_insights": [...],
  "advanced": {
    "shares": ["ADMIN$", "C$", "SYSVOL", "NETLOGON"],
    "pwned": true,
    "dcsync": {...},
    "delegation": {...},
    "rbcd": {...},
    "pkinit": [...]
  }
}
```

**CSV Export:**
```bash
./kerb-sleuth -t dc.corp.local -u admin -p password --csv candidates.csv
```

**SIEM Rules (Sigma):**
```bash
./kerb-sleuth -t dc.corp.local -u admin -p password --siem
# Generates siem_rules.yaml
```

## Output Format

All findings are consolidated into a single `results.json` file (schema version 2.0), including:
- **Domain Metadata**: OS Version, Functional Level, Base DN, and DNS hostname.
- **Summary Statistics**: Total users, AS-REP candidates, Kerberoastable accounts, high-risk objects.
- **Candidates**: Prioritized list of attack targets with scores, reasons, and exploitation paths.
- **Risk Insights**: Automated tactical attack chains and exploitation guidance.
- **Advanced Findings**: SMB shares, GPP credentials, DCSync rights, delegation paths, RBCD configurations, and PKINIT templates.

## Example Workflow

### 1. Initial Reconnaissance
```bash
# Basic enumeration with protocol discovery
./kerb-sleuth -t 10.10.10.100 -u corp\\admin -p P@ssw0rd -d CORP
```

### 2. Secure Connection with Certificate Validation
```bash
# Use LDAPS with CA certificate
./kerb-sleuth -t dc.corp.local -u admin@corp.local -p P@ssw0rd \
  --ldaps --cafile /etc/ssl/certs/corp-ca.pem
```

### 3. Real Kerberos Attacks
```bash
# Extract real AS-REP and Kerberoast hashes
./kerb-sleuth -t dc.corp.local -u admin -p P@ssw0rd -d CORP \
  --real --yes
```

### 4. Hash Cracking
```bash
# Extract and crack hashes with wordlist
./kerb-sleuth -t dc.corp.local -u admin -p P@ssw0rd -d CORP \
  --real --crack -w /usr/share/wordlists/rockyou.txt --yes
```

### 5. Full Advanced Analysis
```bash
# Run all modules: SMB, GPP, RBCD, S4U, DCSync, PKINIT
./kerb-sleuth -t dc.corp.local -u admin -p P@ssw0rd -d CORP \
  -A --yes -o full_analysis.json
```

### 6. Specific Module Analysis
```bash
# Only run DCSync and RBCD analysis
./kerb-sleuth -t dc.corp.local -u admin -p P@ssw0rd -d CORP \
  --dcsync --rbcd --yes
```

### 7. Connection Troubleshooting
```bash
# Automatic TLS fallback if connection fails
./kerb-sleuth -t dc.corp.local -u admin -p P@ssw0rd -d CORP \
  --fallback-tls --insecure
```

## Architecture

### Key Components

**pkg/krb/ldap.go:**
- LDAP connection management with TLS support
- Paged user enumeration (handles >1000 users)
- `SearchSubtreePaged` for efficient large-scale queries
- Certificate validation and CA bundle support

**pkg/krb/kdc.go:**
- Intelligent KDC resolution with multiple fallback methods
- SAM account name extraction from various bind formats

**pkg/krb/kerberos_integration.go:**
- Real Kerberos protocol implementation
- Multi-etype AS-REP roasting (AES256, AES128, RC4)
- Authenticated Kerberoasting with bind credentials
- AES-aware hash formatting for hashcat

**pkg/advanced/:**
- `analyzer.go` - Orchestrates all advanced modules
- `dcsync.go` - DCSync replication rights analysis
- `rbcd.go` - Resource-Based Constrained Delegation
- `s4u.go` - Service for User delegation analysis
- `pkinit.go` - PKINIT/AD CS certificate template enumeration
- `smb.go` - SMB share enumeration and GPP scanning

**pkg/output/writer.go:**
- JSON output with schema versioning
- CSV export for spreadsheet analysis
- Sigma rule generation for SIEM integration

## Security Considerations

### Authorization
Always obtain explicit written authorization before running KERB-SLEUTH against any Active Directory environment. Unauthorized use is illegal and unethical.

### Detection Risk
- **Protocol Discovery**: Port scanning may trigger IDS/IPS alerts
- **Real Kerberos**: AS-REP and TGS-REQ traffic is logged (Event IDs 4768, 4769)
- **SMB Enumeration**: Share access attempts are logged (Event ID 5140)
- **LDAP Queries**: Large-scale enumeration may be detected by SIEM

### Mitigation
- Use `--audit` mode for safer reconnaissance
- Enable rate limiting (built-in 120ms delay for hash extraction)
- Test in isolated lab environments first
- Monitor your own logs to understand detection signatures

## Troubleshooting

### Connection Issues

**Problem:** `LDAP connection failed: dial tcp: i/o timeout`
```bash
# Solution: Try explicit port or fallback TLS
./kerb-sleuth -t dc.corp.local:389 -u admin -p pass --fallback-tls
```

**Problem:** `TLS handshake failed: x509: certificate signed by unknown authority`
```bash
# Solution: Use --insecure or provide CA certificate
./kerb-sleuth -t dc.corp.local -u admin -p pass --ldaps --insecure
# OR
./kerb-sleuth -t dc.corp.local -u admin -p pass --ldaps --cafile ca.pem
```

**Problem:** `LDAP bind failed: Invalid Credentials`
```bash
# Solution: Try different bind formats
./kerb-sleuth -t dc.corp.local -u "CORP\\admin" -p pass
./kerb-sleuth -t dc.corp.local -u "admin@corp.local" -p pass
./kerb-sleuth -t dc.corp.local -u "CN=admin,CN=Users,DC=corp,DC=local" -p pass
```

### Kerberos Issues

**Problem:** `KDC resolution failed`
```bash
# Solution: Explicitly specify KDC
./kerb-sleuth -t dc.corp.local -u admin -p pass --kdc kdc.corp.local
```

**Problem:** `AS-REP extraction failed: KDC returned error: PREAUTH_REQUIRED`
```bash
# This is expected - the account requires pre-authentication (not vulnerable)
```

**Problem:** `Kerberoast extraction failed: GetServiceTicket failed`
```bash
# Solution: Ensure you're using authenticated bind credentials
./kerb-sleuth -t dc.corp.local -u admin -p pass --real --yes
```

## Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Roadmap

- [ ] Structured JSON logging
- [ ] YAML configuration file support
- [ ] Additional hash cracking integrations (John the Ripper)
- [ ] BloodHound integration for attack path visualization
- [ ] Kerberos ticket manipulation (Silver/Golden tickets)
- [ ] Automated exploitation workflows
- [ ] Web-based reporting dashboard

## Credits

Built with:
- [go-ldap/ldap](https://github.com/go-ldap/ldap) - LDAP client library
- [jcmturner/gokrb5](https://github.com/jcmturner/gokrb5) - Kerberos protocol implementation
- [hirochachacha/go-smb2](https://github.com/hirochachacha/go-smb2) - SMB2/3 client library

Inspired by:
- [Rubeus](https://github.com/GhostPack/Rubeus) - C# Kerberos abuse toolkit
- [Impacket](https://github.com/SecureAuthCorp/impacket) - Python network protocol library
- [BloodHound](https://github.com/BloodHoundAD/BloodHound) - AD attack path analysis

## Legal Disclaimer

This tool is designed for authorized security assessments only. Unauthorized use is illegal.

## License

Standard [MIT License](LICENSE).
