# Sentinel — AGENTS.md

> **This file is auto-generated.** It summarizes all context needed to resume work after a conversation reset, including goals, constraints, progress, decisions, and next steps.

## Goal
- Transform the terminal-native offensive security workbench (Sentinel) into a smarter, more capable tool with cross-module correlation, confident-scored attack paths, 9 real modules, a polished TUI, and hardened pipeline.

## Constraints & Preferences
- Rust + Ratatui/Crossterm TUI, Tokio async runtime, all modules real (no mocks)
- Nine modules: port scanner, DNS recon, web enum, SMB enum, credential checker, exploit hunter, privilege escalation strategy, OSINT recon, network discovery
- Attack-path reasoning engine generating prioritized paths from findings
- Educational layer with "What", "Why", "How", "Mitigation", "References" for every finding
- Report generation in Markdown, HTML, JSON, YAML, and plain-text summary
- Seven modes: Beginner, Professional, CTF (aggressive, ~6500 ports, flag hunting), Quick (31 ports only), Stealth, ReconOnly, Full
- No AI, no auto-exploitation, no black-box behavior
- Config file support via `settings.toml`; session history persisted to SQLite
- HTTP proxy support; VPN session management; Docker tool execution

## What We Did This Session

### 1. NetworkDiscovery Module (9th module)
- **ICMP Ping Sweep**: `ping -c 1 -W 2` with 5-second tokio timeout, reports host reachability with TTL
- **Traceroute**: `traceroute -n -m 15` with 30-second tokio timeout, maps network path
- **Network Proximity**: Correlates open port count with ping reachability
- Gracefully handles missing system tools (logs warning, continues)
- Registered in `ModuleRegistry::build_default()` and workflow plan for all modes

### 2. Confidence-Weighted Attack Path Scoring
- `score_path()` in `src/core/correlation.rs` weights adjustments by average finding confidence
- High-confidence findings (≥0.9) give full boost; low-confidence (<0.3) incur penalty
- Applied to all paths (orchestrator built-in + correlated) in `src/core/orchestrator.rs`
- Two new unit tests: `test_score_path_empty_store_no_change`, `test_score_path_high_confidence_boosts_more`

### 3. TUI UI/UX Overhaul
- **Findings panel**: `FindingFilter` enum (All/Critical/High/Medium/Low/Info), toggle via `f` key, sorted by severity descending
- **Attack Paths panel**: Visual Unicode likelihood bars `[███████░░░] 91%`, color-coded green/yellow/dim
- **Status panel**: Horizontal severity bar chart, progress bar with Unicode fill, live running/pending/failed counts
- **Setup panel**: Boxed `┌─┘` layout with input validation hinting, mode selector with `●`/`○` bullets
- **Log panel**: Added `NET` (magenta) tag for NetworkDiscovery module
- **Help overlay**: Updated with `f` keybinding, cleaner sections, wider (64×28)

### 4. Output Deduplication
- Outer headless loop only prints aggregate "Scan Complete" summary for multi-target CIDR (`targets.len() > 1`)
- Eliminates double-print for single targets while preserving multi-target summary

### 5. Module Hardening
- NetworkDiscovery `ping()` and `traceroute()` wrapped with `tokio::time::timeout()`
- `exploit.rs`: Removed unused `make_finding()` test helper to eliminate dead code warning
- Zero warnings across entire project

### 6. Documentation
- **README.md**: Comprehensive docs — features, installation, usage, CLI flags table, TUI keybindings, architecture diagram, module reference, config docs, report format details, Docker tool table, VPN management, development guide, disclaimer
- **LICENSE**: MIT license
- **doc/summary.md**: Detailed architecture overview with all component descriptions
- **doc/MODULES.md**: Complete module reference with capabilities, confidence levels, and integration flow

## Progress
### Done
- **132 unit/integration tests**: target (15), findings (12), workflow (12), orchestrator (22), evidence (17), modules (38), correlation (16)
- **NetworkDiscovery Module (9th)**: ICMP ping sweep with 5s timeout, traceroute with 30s timeout, network proximity assessment; handles missing tools gracefully
- **Confidence-Weighted Scoring**: `score_path()` uses average finding confidence; high-confidence findings boost, low-confidence penalize
- **TUI UI/UX**: Filterable findings (`f` key), visual likelihood bars, severity bar chart, boxed setup layout, updated help overlay, NET log tag
- **Output Deduplication**: Multi-target aggregate summary only for CIDR scans (`targets.len() > 1`)
- **Documentation**: README.md, LICENSE (MIT), doc/summary.md, doc/MODULES.md
- **Module Hardening**: Timeout wrappers on system commands, removed unused code, zero warnings
- **Config file support**: `Settings` struct with `OnceLock` global; `RuntimeOverrides` with `OnceLock<Mutex<>>` for runtime TUI updates
- **SMB null session authentication**: Raw SMBv2 SessionSetup + share TreeConnect (20 shares)
- **HTTP proxy support**: `proxy_url` field in config → `reqwest::Proxy::all()` for web/osint modules
- **Session history (SQLite)**: `SessionDb` with sqlx SQLite backend; save/list/load API
- **Headless mode**: Full pipeline (scan → reports → session save) in non-TTY environments
- **VPN management**: `VpnManager` with OpenVPN/WireGuard lifecycle, TLS cipher auto-fix
- **Docker tool execution**: `DockerManager` with Kali container, 12+ tools, graceful fallback
- **Tool execution library**: nmap/ffuf/nikto/hydra/enum4linux/smbmap/gobuster/searchsploit/sslscan/ldapsearch
- **New WorkflowModes**: Stealth, ReconOnly, Full (7 modes total)
- **Module additions**: SMTP/POP3/IMAP raw auth, WebSocket detection, SMB share enumeration, TLS sslscan, CIDR expansion

### In Progress
- *(none)*

### Blocked
- **HTB VPN `release_arena_sg-release-1`**: TLS handshake fails after certificate verification (server does not accept client cert from this network). Localhost CTF tests validate full pipeline as substitute.

## Key Decisions
- **TUI filter over separate pane**: Flat filter bar (press `f` to cycle) rather than separate filter pane or fuzzy-search; keeps findings panel simple while allowing severity-based narrowing
- **Unicode block bars over ASCII**: `█`/`░` for progress and likelihood bars instead of `#`/`.`; matches Ratatui aesthetic
- **Boxed setup layout**: `┌─└─` unicode-boxed sections for Target, Scan Mode, Options to visually group fields
- **Confidence as multiplier**: Evidence weights multiplied by average confidence rather than summing confidence directly; keeps math bounded while penalizing low-confidence findings
- **MIT License**: Standard permissive license for Rust open-source; matches ecosystem norms
- **Docker global via `OnceLock`**: `DOCKER_MANAGER` static avoids changing `Module` trait signature
- **`impl Fn(&str)` callback pattern**: Docker `initialize()` takes closure for log output instead of mpsc channel
- **Tool installation fails gracefully**: When Kali repos are unreachable, Docker continues with clear messaging
- **TUI-first**: `sentinel` without args → interactive setup; RuntimeOverrides uses Mutex for runtime TUI updates

## Next Steps
1. Test against HTB/THM: Requires working OVPN with valid client cert
2. Add `--resume` flag: Resume an interrupted scan from a session ID
3. Generate wordlists: Bundle common wordlists or download on first use via Docker
4. Set up persistent test infrastructure: HTTP/FTP/SMB services for CI testing
5. Ensure `RuntimeOverrides` exclusion list is checked in port scanner
6. Wire Docker toggle in TUI setup to actually init Docker when scanned from TUI
7. Profile and optimize async scanner concurrency for large CIDR ranges

## Critical Context
- hickory-resolver 0.25 uses generic `lookup()` with `RecordType` for CAA/DNSKEY (convenience methods not available)
- TTL-based OS detection is heuristic: values decrement through hops; confidence capped at 0.85 for single-TTL matches
- Correlation engine paths are additive to existing orchestrator paths — both appear in reports and TUI
- `ping` and `traceroute` must be installed on host for NetworkDiscovery; missing tools produce informational finding
- `FindingFilter` toggled via `f` key in TUI; affects only Findings tab display, not underlying store
- `score_path` uses `avg_confidence` of all findings in store, not per-module
- **Build**: `cargo test` — 132 tests pass in <0.1s; `cargo build --release` — zero warnings, zero errors

## Relevant Files
- `src/modules/network_discovery.rs`: New — 9th module (ping sweep, traceroute, topology) with timeouts
- `src/ui/app.rs`: Enhanced — `FindingFilter` enum, `get_filtered_findings()`, `cycle_filter()`
- `src/ui/mod.rs`: Enhanced — filterable findings panel, visual likelihood bars, severity bar chart, boxed setup layout, 7 keybindings in help, NET log tag
- `src/core/correlation.rs`: Enhanced — `score_path()` uses finding confidence values for weighted adjustment
- `src/core/orchestrator.rs`: Enhanced — confidence-based scoring applied to all paths (built-in + correlated)
- `src/main.rs`: Enhanced — headless deduplication fix, `f` keyhandler for filter cycling
- `src/modules/mod.rs`: Updated — registered `network_discovery`
- `src/core/workflow.rs`: Updated — added `network_discovery` as workflow step
- `README.md`: New — comprehensive project documentation
- `LICENSE`: New — MIT license
- `doc/summary.md`: New — detailed architecture overview
- `doc/MODULES.md`: New — complete module reference
- `settings.toml.example`: Full example config with all options documented
