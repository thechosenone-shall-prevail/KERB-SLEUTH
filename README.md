# Cold Relay

**Identity paths, proven cold.**


Cold Relay is a single-binary Active Directory security assessment tool for authorized operators. It collects Windows authentication evidence across LDAP, Kerberos, SMB, DNS, GPO, delegation, certificate services, sessions, and privilege metadata, then turns that evidence into deterministic findings and an offline attack graph.

It does not claim fake certainty. Findings are marked as `validated`, `likely`, `theoretical`, `blocked`, or `insufficient_visibility`, with evidence, blockers, and next actions attached to the output.

Windows authentication does not fail loudly. It leaves cold traces: stale privilege, readable shares, exposed SPNs, delegated trust, weak certificate paths, forgotten sessions, and directory metadata that quietly explains how a domain can be moved through.

Cold Relay records those traces.

## What It Does

- Enumerates Active Directory users, groups, SPNs, account flags, timestamps, descriptions, and operational metadata.
- Discovers exposed AD-relevant services such as Kerberos, LDAP, SMB, WinRM, RDP, Global Catalog, ADWS, and kpasswd.
- Supports LDAP, LDAPS, STARTTLS, CA validation, insecure TLS mode, and TLS fallback.
- Identifies AS-REP and Kerberoast candidates and can perform real Kerberos hash extraction in aggressive mode.
- Enumerates SMB shares, checks administrative share access, hunts sensitive files, scans SYSVOL, and decrypts GPP `cpassword` values.
- Analyzes trusts, DNS zone transfer exposure, LAPS and gMSA objects, GPO containers, session indicators, privileged objects, RBCD, S4U, DCSync-class rights, and PKINIT/AD CS templates.
- Builds deterministic candidate metadata with validation status, evidence, blockers, and next actions.
- Builds an offline `attack_graph` connecting principals, groups, SPNs, services, shares, files, secrets, sessions, ACL objects, trusts, delegation edges, certificate templates, and replication-right findings.
- Writes JSON, CSV, and optional Sigma detection rules.

## Installation

```bash
git clone https://github.com/thechosenone-shall-prevail/cold-relay.git
cd cold-relay
go build -o cold-relay ./cmd/cold-relay
```

## Quick Start

Passive mode performs protocol discovery, LDAP connection, user enumeration, candidate selection, deterministic validation labeling, and report generation.

```bash
./cold-relay -t 10.129.29.229 \
  -u wallace.everette@logging.htb \
  -p 'Welcome2026@' \
  --mode passive
```

Aggressive mode adds real Kerberos interactions and advanced AD/SMB analysis.

```bash
./cold-relay -t 10.129.29.229 \
  -u wallace.everette@logging.htb \
  -p 'Welcome2026@' \
  --mode aggressive
```

Write JSON, CSV, and Sigma rules:

```bash
./cold-relay -t 10.129.29.229 \
  -u wallace.everette@logging.htb \
  -p 'Welcome2026@' \
  --mode aggressive \
  -o results.json \
  --csv candidates.csv \
  --siem
```

## Command-Line Options

### Primary

| Flag | Description |
|------|-------------|
| `-t <target>` | Target IP or hostname. Required unless supplied positionally. |
| `-u <user>` | Username for authentication. Supports `DOMAIN\user` and `user@domain`. |
| `-p <pass>` | Password for authentication. |
| `-d <domain>` | Domain name. If omitted, Cold Relay attempts RootDSE-based detection. |
| `--mode <passive|aggressive>` | `passive` runs enumeration and reasoning. `aggressive` runs full analysis. |
| `--graph-viewer <results.json>` | Launch local 3D graph viewer from an existing results file (scan not required). |
| `--graph-port <port>` | Port for local graph viewer. Default: `7788`. |

### Output

| Flag | Description |
|------|-------------|
| `-o <file>` | JSON output path. Default: `results.json`. |
| `--csv <file>` | Optional CSV candidate export. |
| `--bloodhound-json <file>` | Optional BloodHound-style JSON graph export. |
| `--bloodhound-csv <file>` | Optional BloodHound-style CSV export base path. |
| `--run-store-dir <dir>` | Optional directory for persisted run metadata artifacts. |
| `--json` | Print JSON to stdout only. |
| `--siem` | Generate Sigma detection rules. |

### Connection And Kerberos

| Flag | Description |
|------|-------------|
| `--ldaps` | Use LDAPS on port 636. |
| `--starttls` | Use STARTTLS on LDAP port 389. |
| `--insecure` | Skip TLS certificate verification. |
| `--cafile <path>` | PEM CA bundle for TLS validation. |
| `--kdc <host>` | Explicit Kerberos KDC hostname or IP. |
| `--fallback-tls` | If plain LDAP fails, try STARTTLS, then LDAPS. |

### Advanced

| Flag | Description |
|------|-------------|
| `-w <wordlist>` | In aggressive mode, extract and attempt cracking candidate hashes with the supplied wordlist. |
| `--audit` | Pass audit mode into advanced analyzers where supported. |
| `--enable-spray` | Explicitly enable credential spray workflow. Disabled by default. |
| `--i-understand-spray-risk` | Required with `--enable-spray` as an explicit safety acknowledgment. |
| `--spray-max-users <n>` | Maximum number of account attempts during spray workflow. Default: `25`. |
| `--spray-delay-ms <n>` | Delay in milliseconds between spray attempts. Default: `750`. |

Credential spraying is intentionally opt-in and gated by explicit acknowledgment.

### 3D Graph Viewer

Launch a local interactive graph viewer (Notion/Obsidian-style exploration) from saved results:

```bash
./cold-relay --graph-viewer results.json --graph-port 7788
```

Then open `http://127.0.0.1:7788` in your browser.

## Validation Language

Cold Relay uses evidence states instead of percentages:

| Status | Meaning |
|--------|---------|
| `validated` | The condition was directly observed or a protocol action succeeded. |
| `likely` | Strong evidence exists, but at least one real-world precondition is not proven. |
| `theoretical` | Directory or configuration data suggests a path, but control or reachability is not proven. |
| `blocked` | The tool attempted a check and could not complete it, or required visibility was denied. |
| `insufficient_visibility` | The collected data is not enough to make a responsible call. |

This is deliberate. LDAP visibility is not exploitability. Delegation is not a reachable chain. SPN presence is not cracked credential value. Session metadata is not host control. Cold Relay keeps that distinction visible in the output.

## Output Model

The JSON report uses schema version `2.0` and is designed to be read offline after collection.

High-level structure:

```json
{
  "schema_version": "2.0",
  "domain": {
    "name": "LOGGING.HTB",
    "dn": "DC=logging,DC=htb",
    "functional_level": "2016",
    "os_version": "Windows Server 2019"
  },
  "summary": {
    "total_users": 12,
    "asrep_candidates": 0,
    "kerberoast_candidates": 0,
    "recon_candidates": 1,
    "hvt_candidates": 2,
    "loot_candidates": 0,
    "validation_status": {
      "validated": 3,
      "likely": 1,
      "theoretical": 2
    }
  },
  "candidates": [
    {
      "SamAccountName": "Administrator",
      "Type": "HVT",
      "Score": 90,
      "validation": "validated",
      "evidence": [
        "LDAP group membership marks this principal as privileged."
      ],
      "blockers": [
        "No current credential, session, or control edge proves access to this principal."
      ],
      "next_actions": [
        "Look for reachable credentials, sessions, ACL writes, or delegation edges into this principal."
      ]
    }
  ],
  "attack_graph": {
    "nodes": [],
    "edges": [],
    "attack_paths": [],
    "summary": {}
  },
  "advanced": {}
}
```

## Attack Graph

Cold Relay builds a graph from collected evidence. The graph is not an AI guess and not a percentage model. It is a deterministic representation of observed objects and relationships.

Graph nodes include:

- `principal`
- `group`
- `target`
- `domain`
- `service`
- `spn`
- `share`
- `file`
- `secret`
- `directory_object`
- `trust`
- `gpo`
- `certificate_template`
- `delegation_account`
- `delegation_target`
- `replication_principal`

Graph edges include:

- `authenticated_to`
- `exposes_service`
- `member_of`
- `owns_spn`
- `exposes_share`
- `contains_sensitive_file`
- `exposes_secret`
- `likely_active_session`
- `marked_privileged`
- `has_trust`
- `tested_axfr`
- `contains_managed_credential`
- `has_gpo`
- `can_act_on_behalf`
- `delegates_to_spn`
- `can_enroll_certificate`
- `has_replication_rights`

Attack paths are generated from these edges with validation status, evidence, and blockers attached.

## Modes

### Passive

Passive mode is the default mode for enumeration and offline reasoning.

It performs:

- Protocol discovery.
- LDAP bind and domain detection.
- Paged user enumeration.
- AS-REP and Kerberoast candidate identification.
- Candidate scoring.
- Validation labeling.
- Attack graph construction from collected evidence.
- JSON/CSV/SIEM output where requested.

### Aggressive

Aggressive mode runs the full assessment surface.

It adds:

- Real Kerberos AS-REP and TGS extraction attempts.
- SMB share enumeration.
- ADMIN$ and C$ access checks.
- SYSVOL GPP scanning and `cpassword` decryption.
- Sensitive file hunting on interesting shares.
- Trust, DNS, LAPS/gMSA, GPO, session, ACL, RBCD, S4U, PKINIT, and DCSync analysis.
- Optional cracking workflow when `-w` is supplied.

## Secure LDAP And KDC Resolution

Cold Relay supports:

- Plain LDAP on 389.
- LDAPS on 636.
- STARTTLS on 389.
- CA bundle validation with `--cafile`.
- Self-signed or lab certificate bypass with `--insecure`.
- Connection fallback with `--fallback-tls`.

KDC resolution order:

1. Explicit `--kdc`.
2. RootDSE `dnsHostName`.
3. LDAP connection host.
4. DNS SRV lookup for `_kerberos._tcp.dc._msdcs.<realm>`.
5. DNS SRV lookup for `_kerberos._tcp.<realm>`.

## Advanced Analysis Surface

### Identity And Privilege

- User enumeration.
- Group membership.
- Admin-marked objects.
- Privileged group membership.
- Inactive account indicators.
- Service account indicators.
- LDAP attribute mining for secret-like material.

### Kerberos

- AS-REP candidate detection.
- Kerberoast candidate detection.
- Multi-etype AS-REP extraction in aggressive mode.
- Authenticated Kerberoasting in aggressive mode.
- KDC resolution and TCP Kerberos framing.

### SMB And File Evidence

- Share enumeration.
- Administrative share access checks.
- SYSVOL GPP XML scanning.
- GPP `cpassword` decryption.
- Sensitive file discovery on interesting shares.
- Secret-like content extraction from readable files.

### Delegation And Replication

- RBCD target enumeration.
- S4U delegation analysis.
- DCSync-class extended-right detection where readable.
- Exploitation-path reporting with validation caveats.

### Infrastructure

- Protocol discovery.
- Domain trust enumeration.
- DNS zone transfer checks.
- LAPS and gMSA enumeration.
- Group Policy container analysis.
- Session intelligence from LDAP timestamps and logon counts.
- PKINIT and AD CS certificate template analysis.

## CSV Output

CSV output includes:

- `SamAccountName`
- `Type`
- `Score`
- `Severity`
- `Validation`
- `Reasons`
- `Evidence`
- `Blockers`
- `NextActions`
- `SPNs`
- `ExportHashPath`

## SIEM Output

`--siem` writes Sigma-style detections for common Kerberos attack signals such as AS-REP roasting and Kerberoasting.

```bash
./cold-relay -t dc01.corp.local -u alice@corp.local -p 'Password123!' --mode aggressive --siem
```

## Build And Test

```bash
go test ./...
go vet ./...
go build -o cold-relay ./cmd/cold-relay
```

## Docker

```bash
docker build -t cold-relay .
docker run --rm -it cold-relay --help
```

## Security And Authorization

Cold Relay is for authorized security work only.

Protocol discovery, LDAP enumeration, Kerberos requests, SMB share access, SYSVOL traversal, and file reads can generate logs and trigger controls. Run it only in environments where you have permission to test.

Detection examples:

- Kerberos AS-REQ and TGS-REQ traffic can generate Windows Security events such as 4768 and 4769.
- SMB share access can generate share access events such as 5140.
- LDAP enumeration can be visible to directory monitoring and SIEM tooling.
- DNS AXFR attempts may be logged by DNS infrastructure.

Use lab environments first. Understand what each mode does before running it in a production network.

## Philosophy

Cold Relay is built around operator trust.

It should tell you:

- What was observed.
- Why it matters.
- What is proven.
- What is only suggested.
- What blocked validation.
- What an operator should check next.

It should not pretend a directory relationship is a compromise. It should not dress a heuristic as mathematics. Active Directory attack paths are stateful, environmental, and conditional. Cold Relay keeps those conditions visible.

## Credits

Built with:

- [go-ldap/ldap](https://github.com/go-ldap/ldap)
- [jcmturner/gokrb5](https://github.com/jcmturner/gokrb5)
- [hirochachacha/go-smb2](https://github.com/hirochachacha/go-smb2)
- [miekg/dns](https://github.com/miekg/dns)

Inspired by the practical lessons of mature AD assessment tooling and by the operator workflow of moving from evidence to validation, not from guesses to noise.

## License

MIT. See [LICENSE](LICENSE).
