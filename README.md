# Active Directory Kerberos Security Scanner

![GitHub license](https://img.shields.io/github/license/thechosenone-shall-prevail/KERB-SLEUTH) ![GitHub stars](https://img.shields.io/github/stars/thechosenone-shall-prevail/KERB-SLEUTH) ![Go version](https://img.shields.io/github/go-mod/go-version/thechosenone-shall-prevail/KERB-SLEUTH) ![Platform](https://img.shields.io/badge/platform-windows-blue)

🩸 BLEEDING WINDOWS AUTHENTICATION 🩸

A production-ready, single-binary Go tool for identifying AS-REP and Kerberoastable targets in Active Directory environments, combined with deep reconnaissance and automated protocol discovery.

## Core Capabilities

- **Identity Reconnaissance**: Automated enumeration of all user objects, including detailed attributes such as descriptions, group memberships (MemberOf), and account security flags (UAC).
- **Kerberos Attacks**: Targeted discovery of AS-REP roastable and Kerberoastable service accounts with built-in scoring for prioritization.
- **Protocol Discovery**: Rapid service checking for LDAP (389), SMB (445), WinRM (5985), RDP (3389), and RPC (135) with colored terminal "hits."
- **Administrative "Pwned" Detection**: Real-time detection of administrative privileges by attempting access to ADMIN$ and C$ shares.
- **Credential Harvesting**: Automated scanning of SYSVOL for Group Policy Preferences (GPP) XML files and decryption of `cpassword` attributes.
- **Advanced Attack Vectors**: Built-in support for analyzing RBCD, S4U delegation paths, and DCSync replication rights.

## Installation

```bash
git clone https://github.com/thechosenone-shall-prevail/KERB-SLEUTH.git
cd KERB-SLEUTH
go build -o kerb-sleuth ./cmd/kerb-sleuth/
```

## Usage

### Deep Dive Analysis (All Modules)
```bash
./kerb-sleuth <target_ip> -u <user> -p <pass> -d <domain> -A
```

## Output Format

All findings are consolidated into a single `results.json` file, including:
- **Domain Metadata**: OS Version, Functional Level, and Base DN.
- **Recon Insights**: Automated flagging of high-risk accounts and unique group counts.
- **Advanced Findings**: SMB shares, GPP credentials, and delegation paths.

## Legal Disclaimer

This tool is designed for authorized security assessments only. Unauthorized use is illegal.

## License

Standard [MIT License](LICENSE).
