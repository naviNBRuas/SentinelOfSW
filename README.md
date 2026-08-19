# Sentinel — Terminal-Native Offensive Security Workbench

[![Rust](https://img.shields.io/badge/rust-1.75%2B-blue.svg)](https://www.rust-lang.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**Sentinel** is a terminal-native offensive security workbench built in Rust. It performs intelligent enumeration, explains findings with educational context, prioritizes attack paths using cross-module correlation, and generates structured evidence reports — all from a modern Ratatui-based TUI or headless CLI.

---

## Features

- **9 Scanner Modules**: Port scanner (async TCP, banner grabbing, OS detection), DNS recon (subdomains, SRV/CAA/DNSSEC), web enumeration (directory brute-force, tech detection, security headers, WebSocket, TLS), SMB enumeration (null session, share TreeConnect, signing checks), credential checker (default creds, SMTP/POP3/IMAP auth, hydra), exploit hunter (per-port CVE matching), privilege escalation strategy, OSINT recon (crt.sh, DNS records, WHOIS), network discovery (ping, traceroute)
- **7 Workflow Modes**: Beginner, Professional, CTF (aggressive, ~6500 ports, flag hunting, OSINT), Quick (31 ports only, ~3 min), Stealth (evasion, jitter, low concurrency), ReconOnly (DNS + ports only), Full (maximum aggressiveness, all modules)
- **Adaptive Orchestration**: A deterministic, fully-auditable trigger engine that reacts to discoveries *during* a scan and schedules follow-up work that was never in the static plan — e.g. a credential found on one service (or leaked in an exposed `.env`) is automatically validated across every other auth-capable service (**credential reuse**), and exposed `.env`/`.git/config` files are fetched and parsed for secrets that feed back into the credential pool (**secret harvest**, a depth-2 chain). No AI, no black box: every scheduled action is logged with its rationale (`CHAIN` log tag) and bounded by hard iteration caps.
- **Attack Path Reasoning**: Cross-module correlation engine that generates prioritized, evidence-scored attack paths from combined findings (e.g., creds + web panel → Credentialed Web Access, SMB + null session → data harvesting, Docker API → container escape)
- **Educational Layer**: Every finding includes "What", "Why", "How", "Mitigation", and "References" explanations — great for learning and CTF write-ups
- **Report Generation**: Markdown, HTML, JSON, YAML, and plain-text summary — saved to `./reports/<target>_<timestamp>/`
- **Interactive TUI**: Full-screen Ratatui terminal UI with real-time module output, severity-filterable findings, visual attack path charts, and live progress tracking
- **Headless Mode**: JSON or text output for automation, CI/CD, and server environments without a real terminal
- **Docker Tool Execution**: Pulls Kali Linux container, installs 12+ pentesting tools (nmap, ffuf, nikto, hydra, gobuster, enum4linux-ng, smbmap, searchsploit, sslscan, dnsrecon, whois), falls back to built-in scanners when internet is unavailable
- **VPN Session Management**: OpenVPN and WireGuard lifecycle management via `--vpn` flag
- **Session History**: All scan results persisted to SQLite (`sentinel_history.db`) — browse and replay past sessions with `--history` and `--history-id`
- **Config File**: Optional `settings.toml` with customizable port lists, timeouts, concurrency, wordlists, and proxy settings
- **Confidence-Weighted Scoring**: Attack path likelihood adjusted by actual finding confidence values — paths with high-confidence findings get the largest boost
- **CIDR Support**: Expand `/16` to 65536 hosts, each scanned independently with per-target and aggregate reporting

---

## Installation

### Prerequisites

- **Rust 1.75+** (stable)
- **OpenSSL** development headers (for `reqwest`)
- **SQLite** (for session history)

### Build from source

```bash
git clone https://github.com/yourusername/sentinel.git
cd sentinel
cargo build --release
./target/release/sentinel --help
```

### Optional Dependencies

For the Docker tool execution mode (`--docker`):

- Docker CE or EE installed and running
- Internet access to pull `kalilinux/kali-rolling`

For VPN management (`--vpn`):

- OpenVPN or WireGuard installed

---

## Usage

### Quick Start

```bash
# Interactive TUI (no target → setup screen)
sentinel

# Beginner scan (default)
sentinel 10.10.10.10

# Quick scan (31 ports, ~3 minutes)
sentinel --quick scanme.nmap.org

# CTF mode — aggressive, all modules, flag hunting
sentinel --ctf 10.10.10.10

# Headless mode (no TUI required)
sentinel --headless --quick 10.10.10.10

# JSON output for automation
sentinel --headless --json 10.10.10.10 > results.json

# Dive into a CIDR range
sentinel --quick 10.10.10.0/24
```

### All Modes

| Mode | Flag | Description | Ports | Est. Time |
|------|------|-------------|-------|-----------|
| Beginner | *(default)* | Verbose, educational, all modules | ~170 | ~15 min |
| Professional | `-p` | Concise output, minimal explanations | ~170 | ~8 min |
| CTF | `-c` | Aggressive, flag hunting, OSINT | ~6500 | ~10 min |
| Quick | `-q` | Fast, common ports only | 31 | ~3 min |
| Stealth | `--stealth` | Evasion: jitter, no banners, slow | ~170 | ~25 min |
| ReconOnly | `--recon-only` | DNS recon + port scan only | ~170 | ~5 min |
| Full | `--full` | All modules, maximum aggressiveness | ~170 | ~20 min |

### CLI Flags

```
General:
  -n, --headless       No TUI, print progress to stdout
  -q, --quick          Quick scan (31 common ports)
  -c, --ctf            CTF mode (aggressive, ~6500 ports, flag hunting)
  -p, --professional   Professional mode (concise, minimal explanations)
  --recon-only         Recon-only mode (DNS + port scan only)
  --full               Full mode (all modules, aggressive)
  --stealth            Stealth mode (evasion, jitter, low concurrency)

Networking:
  --threads <N>        Concurrency threads (overrides config)
  --rate-limit <MS>    Rate limit in ms between probes
  --timeout <SEC>      Global timeout in seconds
  --exclude-ports <P>  Comma-separated ports to skip (e.g., "22,80,443")

Docker:
  --docker             Enable Docker mode (Kali Linux container tools)
  --docker-image <IMG> Docker image (default: kalilinux/kali-rolling)

VPN:
  --vpn <NAME>         VPN config name (from ./vpn/ directory)
  --vpn-list           List available VPN configs and exit

Output:
  --json               Machine-readable JSON output (headless only)
  --no-report          Skip report generation
  --output-dir <PATH>  Custom report output directory (default: ./reports/)

History:
  --history            List past sessions from database
  --history-id <N>     Load and display a specific session by ID

Config:
  --help               Show full help with examples
```

### Examples

```bash
# Full pipeline with VPN + Docker on CTF target
sentinel --vpn htb-eu --docker --ctf 10.10.10.10

# Stealth scan with custom output directory
sentinel --stealth --output-dir /tmp/scan-results target.local

# Exclude high-traffic ports, increase concurrency
sentinel --threads 100 --exclude-ports 80,443 10.10.10.10

# Quick CIDR scan with JSON output
sentinel --headless --json --quick 10.0.0.0/28 > cidr-scan.json

# Scan + save reports, then view history
sentinel 10.10.10.10
sentinel --history
sentinel --history-id 42
```

---

## TUI (Terminal UI)

Running `sentinel` without a target opens the **interactive setup**:

```
┌─────────────────────────────────────────────────────┐
│  SENTINEL SECURITY WORKBENCH │ ○ SETUP │ Target:   │
├─────────────────────────────────────────────────────┤
│ ┌─ Target ────────────────────────────────────────┐ │
│ │  Enter IP, domain, or CIDR                    █ │ │
│ │  ✓ Valid input                                  │ │
│ └─────────────────────────────────────────────────┘ │
│ ┌─ Scan Mode ────────────────────────────────────┐ │
│ │  ▸ ● Beginner     Verbose, educational, all    │ │
│ │    ○ Professional Concise, minimal explanations│ │
│ │    ○ CTF          Aggressive, flag hunting     │ │
│ └─────────────────────────────────────────────────┘ │
│ ┌─ Options ──────────────────────────────────────┐ │
│ │  ☐ Docker   Kali Linux container tools         │ │
│ │  ☐ Stealth  Evasion, jitter, low concurrency   │ │
│ │  ☐ NoReport Skip report generation             │ │
│ └─────────────────────────────────────────────────┘ │
│  ▶ LAUNCH SCAN — 10.10.10.10                       │
├─────────────────────────────────────────────────────┤
│ [?] Help │ [q] Quit                                 │
└─────────────────────────────────────────────────────┘
```

### Keybindings

| Key | Action |
|-----|--------|
| Tab / Shift+Tab | Navigate fields |
| ↑ / ↓ | Change mode / scroll content |
| Space | Toggle flag |
| Enter | Start scan / select item |
| 1-6 | Jump to tab |
| S | Setup tab |
| f | Cycle finding severity filter |
| ? | Toggle help overlay |
| q / Esc | Quit |

### Tabs

| Tab | Content |
|-----|---------|
| Setup | Configure and launch a scan |
| Status | Overview, progress bar, severity breakdown |
| Findings | Discovered findings (filterable by severity) |
| Paths | Attack path analysis with visual likelihood bars |
| Workflow | Scan plan and task execution status |
| Education | Detailed explanations for each finding |
| Log | Live module output feed |

---

## Architecture

```
sentinel/
├── src/
│   ├── main.rs              # Entry point, CLI, headless/TUI dispatch
│   ├── core/
│   │   ├── adaptive.rs      # Adaptive orchestration engine (trigger rules, ScanContext blackboard)
│   │   ├── config.rs        # Settings (TOML), RuntimeOverrides
│   │   ├── correlation.rs   # Cross-module finding correlation engine
│   │   ├── docker.rs        # Docker container management
│   │   ├── evidence.rs      # Report generation (MD/HTML/JSON/YAML/TXT)
│   │   ├── findings.rs      # Finding, AttackPath, FindingStore
│   │   ├── knowledge.rs     # Educational notes for all finding types
│   │   ├── orchestrator.rs  # Workflow orchestrator, task graph
│   │   ├── session.rs       # SQLite session persistence
│   │   ├── target.rs        # Target detection (IP/domain/CIDR/URL)
│   │   ├── tools.rs         # Docker tool wrappers (nmap, ffuf, etc.)
│   │   ├── vpn.rs           # OpenVPN/WireGuard lifecycle
│   │   └── workflow.rs      # WorkflowMode, WorkflowPlan, WorkflowEngine
│   ├── modules/
│   │   ├── mod.rs           # Module trait, ModuleRegistry
│   │   ├── creds.rs         # Default credential checker
│   │   ├── exploit.rs       # Exploit hunter (per-port CVEs)
│   │   ├── network_discovery.rs # Ping sweep, traceroute
│   │   ├── osint.rs         # OSINT recon (crt.sh, DNS, WHOIS)
│   │   ├── port_scanner.rs  # Async TCP port scanner
│   │   ├── priv_esc.rs      # Privilege escalation strategy
│   │   ├── recon.rs         # DNS reconnaissance
│   │   ├── smb.rs           # SMB enumeration
│   │   └── web.rs           # Web enumeration
│   └── ui/
│       ├── app.rs           # App state, tab/setup/field navigation
│       └── mod.rs           # Ratatui render functions
├── vpn/                     # VPN configuration files
├── wordlists/               # Custom wordlist files
├── settings.toml.example    # Example configuration
└── sentinel_history.db      # Session database (auto-created)
```

### Modules

| Module | Name | What It Does |
|--------|------|-------------|
| `recon` | DNS Recon | Subdomain enumeration, SRV/CAA/DNSSEC records, zone transfer check |
| `port_scan` | Port Scanner | Async TCP connect scan, banner grabbing, OS detection via TTL |
| `web` | Web Enumeration | Directory brute-force, tech detection, security headers, flag hunting |
| `smb` | SMB Enumeration | Null session detection, share enumeration, signing checks |
| `creds` | Credential Checker | Default creds (FTP/SSH/HTTP/MySQL/Postgres/Redis), SMTP/POP3/IMAP auth |
| `exploit` | Exploit Hunter | Port-to-CVE mapping (EternalBlue, BlueKeep, regreSSHion, etc.) |
| `priv_esc` | PrivEsc Strategy | Linux/Windows PE checklists, Docker escape, K8s API, NFS |
| `osint` | OSINT Recon | crt.sh, MX/NS/PTR/TXT records, WHOIS, subdomain brute-force |
| `network_discovery` | Network Discovery | ICMP ping sweep, traceroute, network proximity assessment |

---

## Adaptive Orchestration

Most scanners run a fixed list of checks. Sentinel runs a fixed plan **and then
reacts to what it found** — deterministically, with no AI and no hidden state.

After the static workflow plan completes, the **adaptive engine**
(`src/core/adaptive.rs`) repeatedly evaluates a small set of trigger rules
against the live findings and a shared `ScanContext` blackboard, scheduling
bounded follow-up module runs:

| Chain | Trigger | Follow-up action |
|-------|---------|------------------|
| **Credential Reuse** | A credential is proven on any service (default cred, or harvested) | Validate that credential against every *other* auth-capable open port (SSH/FTP/SMB/RDP/WinRM/MySQL/Postgres/…) |
| **Secret Harvest** | An exposed `.env` / `.git/config` is discovered by the web module | Fetch and parse it for credentials, feed them into the pool → re-triggers Credential Reuse (depth-2 chain) |

**Guarantees:**

- **Deterministic & auditable** — every scheduled action is printed with its
  rationale under the `CHAIN` log tag and flows into the same findings, attack
  paths, and reports as everything else.
- **Bounded** — a hard `max_rounds` (3) + global follow-up cap, plus a
  per-trigger dedup set, guarantee termination. A rule only re-fires when
  genuinely new state appears (e.g. a newly leaked credential).
- **No new capability surface** — chains only perform credential *validation*
  and read *already-exposed* files (the same classes of action the `creds` and
  `web` modules already perform). No command execution, no post-exploitation.

Example (against a target serving an exposed `.env`):

```
[CHAIN] Round 1: web → exposed source/config files detected → harvesting 1 URL(s)
[Web Enum] Harvested 2 credential(s) from http://target/.env
[CHAIN] Round 2: creds → 3 discovered credential(s) → validating reuse across all auth-capable services
[Creds] REUSE SUCCESS: deploy:hunter2 @ HTTP:8080
```

---

## Configuration

Copy `settings.toml.example` to `settings.toml` in the working directory:

```bash
cp settings.toml.example settings.toml
```

All values have sensible defaults. The config file supports:

- **Port lists** — custom defaults for each mode (Beginner, CTF, Quick)
- **Timeouts** — connect, HTTP, DNS, and banner timeouts per service
- **Concurrency** — batch sizes and semaphore limits per module
- **Scan options** — report path, user agents
- **HTTP proxy** — for web/OSINT modules (or use `HTTP_PROXY`/`HTTPS_PROXY` env vars)
- **Wordlists** — external wordlist files for subdomains, directories, and CTF files

---

## Reports

Reports are saved to `./reports/<target>_<timestamp>/` (or `--output-dir` override):

```
reports/
└── 10_10_10_10_20260203_143022/
    ├── summary.txt    # Plain-text executive summary
    ├── report.md      # Markdown report with severity counts
    ├── report.html    # Interactive HTML with findings and paths
    ├── report.json    # Machine-readable JSON for automation
    ├── report.yaml    # YAML structured data
    └── evidence/      # Raw evidence files (if applicable)
```

---

## Session History

All completed scans are automatically saved to `sentinel_history.db`:

```bash
# List all past sessions
sentinel --history

# Load a specific session
sentinel --history-id 42

# Re-run from session data (future: --resume)
```

---

## Docker Tool Execution

The `--docker` flag enables running industry-standard tools inside a Kali Linux container:

| Tool | Use Case |
|------|----------|
| `nmap` | Port scanning with service version detection |
| `ffuf` | Web directory/content fuzzing |
| `nikto` | Web server vulnerability scanning |
| `hydra` | Online password brute-forcing |
| `gobuster` | DNS and directory brute-forcing |
| `enum4linux-ng` | SMB/Linux enumeration |
| `smbmap` | SMB share access checking |
| `smbclient` | SMB file operations |
| `searchsploit` | Offline exploit-db search |
| `sslscan` | TLS/SSL cipher and certificate analysis |
| `dnsrecon` | Advanced DNS enumeration |
| `whois` | Domain registration lookups |

The container is pulled on first use and cached. If Kali repos are unreachable (no internet/VPN), Sentinel gracefully falls back to built-in scanners.

---

## VPN Management

Place `.ovpn` (OpenVPN) or `.conf` (WireGuard) files in `./vpn/`:

```bash
# List available configs
sentinel --vpn-list

# Connect and scan through VPN
sentinel --vpn htb-eu --ctf 10.10.10.10

# Use with Docker for off-platform tool execution
sentinel --vpn htb-eu --docker --ctf 10.10.10.10
```

---

## Development

```bash
# Run tests
cargo test

# Build release
cargo build --release

# Run with live reload during development
cargo watch -x run -- --headless --quick scanme.nmap.org
```

### Testing

```bash
# All unit/integration tests
cargo test

# Specific module tests
cargo test -- test_correlate
cargo test -- test_port_scanner
```

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

## Disclaimer

Sentinel is a security assessment tool intended for authorized testing of systems you own or have explicit permission to test. Unauthorized scanning of systems is illegal in many jurisdictions. The authors assume no liability for misuse.
