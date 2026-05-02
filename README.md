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
[![Go version](https://img.shields.io/badge/Go-1.23+-00ADD8?style=for-the-badge&logo=go)](https://golang.org/)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey?style=for-the-badge)](https://github.com/thechosenone-shall-prevail/KERB-SLEUTH/releases)

**🩸 BLEEDING WINDOWS AUTHENTICATION 🩸**

*A production-ready, single-binary Go tool for identifying AS-REP and Kerberoastable targets in Active Directory environments. Designed for offline-first operation with safe-by-default behavior.*

</div>

---

## 🎯 **ERIGONOMIC & EFFICIENT**

KERB-SLEUTH v2.0 is designed for speed and zero-noise. No complex subcommands or simulated data—just point it at a DC and let it hunt.

### **Quick Start**
```bash
# Basic anonymous scan (auto-detects LDAP/LDAPS)
kerb-sleuth 10.10.10.100

# Authenticated full scan with all advanced modules
kerb-sleuth 10.10.10.100 -u jsmith -p P@ssw0rd123 -d corp.local -A

# Extract hashes and auto-crack with hashcat/john
kerb-sleuth 10.10.10.100 -u user -p pass --crack --yes
```

---

## 🛠️ **CORE FEATURES**

- **Smart Auto-Detection**: Automatically negotiates LDAP/LDAPS/StartTLS.
- **Position-Independent CLI**: Target can be anywhere in the command.
- **Real Protocol Implementation**: True AS-REQ/TGS-REQ roasting (no fakes).
- **Advanced AD Enumeration**: RBCD, S4U, DCSync, and AD CS (PKINIT) analysis.
- **Zero Noise**: Pruned of >70% bloat; focused entirely on real-world reliability.
- **Offline Mode**: Analyze CSV/JSON/LDIF exports with `kerb-sleuth -f users.csv`.

---

## 🚩 **COMMON FLAGS**

| Flag | Description |
| :--- | :--- |
| `<target>` | DC IP or Hostname (can be anywhere in command) |
| `-u` | Username (`user`, `DOMAIN\user`, or `user@domain`) |
| `-p` | Password |
| `-d` | Domain name (auto-detected if omitted) |
| `-k` | Skip TLS certificate verification (Insecure mode) |
| `-A` | **Full Advanced Analysis** (RBCD, S4U, DCSync, PKINIT) |
| `--crack` | Extract hashes and run cracker (requires `--yes`) |
| `-o` | Custom output file (default: `<target>_results.json`) |
| `-f` | Offline file analysis (CSV/JSON/LDIF) |

---

## 🚀 **INSTALLATION**

```bash
# Build from source
git clone https://github.com/thechosenone-shall-prevail/KERB-SLEUTH.git
cd KERB-SLEUTH && go build -o kerb-sleuth ./cmd/kerb-sleuth
```

---

<div align="center">

**⭐ Star this repo if you find it useful! ⭐**

*Made with :D by [@thechosenone-shall-prevail](https://github.com/thechosenone-shall-prevail)*

</div>
