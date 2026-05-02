# KERB-SLEUTH: Active Directory Kerberos Security Scanner

**🩸 BLEEDING WINDOWS AUTHENTICATION 🩸**

A production-ready, single-binary Go tool designed for deep reconnaissance and automated exploitation of Windows Active Directory environments. KERB-SLEUTH combines the speed of Go with the depth of industry-standard tools like NetExec to provide a comprehensive security overview in a single JSON report.

## Core Capabilities

- **Identity Reconnaissance**: Automated enumeration of all user objects, including detailed attributes such as descriptions, group memberships (MemberOf), and account security flags (UAC).
- **Kerberos Attacks**: Targeted discovery of AS-REP roastable and Kerberoastable service accounts with built-in scoring for prioritization.
- **Protocol Discovery**: Rapid service checking for LDAP (389), SMB (445), WinRM (5985), RDP (3389), and RPC (135) with colored terminal "hits."
- **Administrative "Pwned" Detection**: Real-time detection of administrative privileges by attempting access to ADMIN$ and C$ shares.
- **Credential Harvesting**: Automated scanning of SYSVOL for Group Policy Preferences (GPP) XML files and decryption of `cpassword` attributes.
- **Advanced Attack Vectors**: Built-in support for analyzing RBCD (Resource-Based Constrained Delegation), S4U delegation paths, and DCSync replication rights.

## Installation

Ensure you have Go installed on your system.

```bash
git clone https://github.com/thechosenone-shall-prevail/KERB-SLEUTH.git
cd KERB-SLEUTH
go build -o kerb-sleuth ./cmd/kerb-sleuth/
```

## Usage

### Basic Authenticated Scan
```bash
./kerb-sleuth <target_ip> -u <user> -p <pass> -d <domain>
```

### Deep Dive Analysis (All Modules)
```bash
./kerb-sleuth <target_ip> -u <user> -p <pass> -d <domain> -A
```

### Full Recon & Hash Extraction
```bash
./kerb-sleuth <target_ip> -u <user> -p <pass> --crack --yes
```

## Output Format

KERB-SLEUTH prioritizes clean, actionable data. All findings are consolidated into a single `results.json` file, including:
- **Domain Metadata**: OS Version, Functional Level, and Base DN.
- **Recon Insights**: Automated flagging of high-risk accounts and unique group counts.
- **Advanced Findings**: SMB shares, GPP credentials, and delegation paths.

## Legal Disclaimer

This tool is designed for authorized security assessments and educational research only. Unauthorized access to computer systems is illegal. The developers assume no liability for misuse of this utility.

## License

Standard [MIT License](LICENSE).
