# Kerb-Sleuth

[![CI](https://github.com/yourusername/kerb-sleuth/actions/workflows/ci.yml/badge.svg)](https://github.com/yourusername/kerb-sleuth/actions)

A production-ready, single-binary Go tool for identifying AS-REP and Kerberoastable targets in Active Directory environments. Designed for offline-first operation with safe-by-default behavior.

## ⚠️ Legal Warning

**This tool is for authorized security assessments only.** Unauthorized access to computer systems is illegal and punishable by law. Always ensure you have explicit written permission before using this tool in any environment.

## Features

- **Offline-First Design**: Operates primarily on exported AD data (CSV, LDIF, JSON)
- **AS-REP Roasting Detection**: Identifies accounts with pre-authentication disabled
- **Kerberoasting Detection**: Finds accounts with Service Principal Names (SPNs)
- **Intelligent Scoring**: Configurable heuristics for risk assessment
- **Multiple Output Formats**: JSON, CSV, and Sigma rule generation
- **Safe by Default**: Requires explicit authorization for sensitive operations
- **Single Binary**: Easy deployment with minimal dependencies

## Installation

### Pre-built Binaries
Download the latest release from the [releases page](https://github.com/yourusername/kerb-sleuth/releases).

### Build from Source
```bash
git clone https://github.com/yourusername/kerb-sleuth.git
cd kerb-sleuth
make build
```

## Quick Start

1. Export AD user data to CSV:
```powershell
# PowerShell example
Get-ADUser -Filter * -Properties * | Export-Csv users.csv
```

2. Run kerb-sleuth:
```bash
kerb-sleuth scan --ad users.csv --out results.json
```

3. Review results:
```bash
cat results.json | jq '.summary'
```

## Usage

### Basic Scan
```bash
kerb-sleuth scan --ad users.csv --out results.json
```

### With Additional Outputs
```bash
kerb-sleuth scan --ad users.csv --out results.json --csv --siem
```

### Generate Test Data
```bash
kerb-sleuth simulate --dataset small --out tests/sample_data/
```

### Hash Export (Requires Authorization)
```bash
kerb-sleuth scan --ad users.csv --crack --i-am-authorized
```

## Configuration

Customize scoring weights and thresholds via `configs/defaults.yml`:

```yaml
weights:
  asrep_base: 50
  asrep_preauth: 20
  asrep_pwd_old: 15
  
thresholds:
  high: 80
  medium: 50
```

## Output Formats

### JSON Output
Detailed results with scoring and reasons:
```json
{
  "summary": {
    "total_users": 100,
    "asrep_candidates": 5,
    "kerberoast_candidates": 10
  },
  "candidates": [
    {
      "sam": "sqlsvc",
      "type": "KERBEROAST",
      "score": 85,
      "reasons": ["Has Service Principal Names", "Password older than 90 days"]
    }
  ]
}
```

### CSV Summary
Simplified tabular format for reporting.

### Sigma Rules
Generated detection rules for SIEM integration.

## Development

### Running Tests
```bash
make test
```

### Building for Multiple Platforms
```bash
make build-all
```

### Contributing
See [CONTRIBUTING.md](CONTRIBUTING.md) for development guidelines and safety policies.

## Security Considerations

- Default behavior is read-only and offline
- Network operations require explicit `--i-am-authorized` flag
- Cracking features are disabled by default
- All exports include legal warnings

## License

MIT License - See [LICENSE](LICENSE) file for details.

## Disclaimer

This tool is provided for authorized security testing only. The authors assume no liability for misuse or damage caused by this program.
