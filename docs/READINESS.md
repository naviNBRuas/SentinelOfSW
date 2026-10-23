# E17.04 — SentinelOfSW: production-ready definition and gap list

## Current state

What is actually built and working today, with file paths:

- **Build**: `cargo check --offline` and `cargo build --offline` complete successfully (E17/21 local verification)
- **Tests**: `cargo test --offline` passes all 160 local unit tests (E17/21 verification; no live scan)
- **Version**: CLI derives its version from Cargo package metadata (`0.1.1`)
- **Core modules** (9 total, all implemented):
  - `src/modules/recon.rs` — DNS reconnaissance with subdomain enumeration, SRV/CAA/DNSSEC records, zone transfer
  - `src/modules/port_scanner.rs` — Async TCP port scanner with service identification and OS fingerprinting
  - `src/modules/web.rs` — HTTP enumeration with directory brute-force, technology detection, security headers
  - `src/modules/smb.rs` — SMB/CIFS enumeration with null session detection and share probing
  - `src/modules/creds.rs` — Default/weak credential testing across 7 service types
  - `src/modules/exploit.rs` — CVE mapping per port (20+ port/CVE mappings)
  - `src/modules/priv_esc.rs` — Privilege escalation strategies for Linux, Windows, Docker, K8s
  - `src/modules/osint.rs` — Certificate transparency, MX/NS/TXT/SPF records, WHOIS lookup
  - `src/modules/network_discovery.rs` — ICMP ping sweep and traceroute
- **Module registry**: `src/core/module.rs` — `ModuleRegistry::build_default()` registers all 9 modules
- **Two-phase execution pipeline**: Phase 1 unconditional (recon → port_scan), Phase 2 regenerated plan based on discovered ports
- **Session persistence**: SQLite via `src/core/session.rs` — `SessionDb` with `started_at`/`completed_at` RFC3339 timestamps, saves/loads findings and attack paths
- **Report generation**: configurable output directory via `Settings::global().report_path()` or `--output-dir` CLI flag; writes summary.txt, report.md, report.html, report.json, report.yaml
- **Evidence management**: `src/core/evidence.rs` — `EvidenceManager::with_path(target, &report_path)` organizes output
- **CLI**: Clap-based with `--target`, `--mode`, `--output-dir`, `--docker`, `--vpn <name>` flags
- **TUI**: Interactive setup screen with `ratatui`; `--output-dir` propagates to both immediate-target and setup-started scanners, falling back to the configured report path when omitted (local option tests and source review; no live scan)
- **VPN management**: `src/core/vpn.rs` — OpenVPN/WireGuard configs in `./vpn/` referenced by `--vpn <name>`
- **Configuration**: `settings.toml.example` with `[ports]`, `[timeouts]`, `[concurrency]`, `[scan]` sections; all values have built-in defaults
- **Dependencies**: `tokio 1.42`, `reqwest 0.12`, `sqlx 0.8`, `ratatui 0.29`, `petgraph 0.6`, `clap 4.5`
- **160 local unit tests**, including CLI report-directory and version regressions, all passing offline

**Commands verified**:
- `cargo test --offline` — 160 passed, 0 failed (E17/21 local verification)
- `cargo check --offline` and `cargo build --offline` — complete successfully (E17/21 local verification)

**E17/21 scope**: report-directory plumbing and CLI version consistency are corrected locally. Overall readiness, live protocol behavior and E36/04 repository integrity limitations remain open.

## Production-ready definition

For Sentinel to be considered production-ready, all of the following must be true:

1. [ ] All 9 core modules pass their unit tests and can run headless scans end-to-end
2. [ ] Adaptive orchestration engine reliably triggers credential reuse and secret-harvest chains without infinite loops
3. [ ] TUI renders correctly under various terminal sizes; `--output-dir` flag propagates to TUI sessions
4. [ ] Headless mode produces consistent, machine-readable output (JSON, YAML, Markdown) across all scan modes
5. [ ] Docker tool execution falls back gracefully to built-in scanners when internet access is unavailable
6. [ ] Session history via `sentinel_history.db` persists and replays scans accurately (started_at/completed_at timestamps stored as RFC3339)
7. ✅ All CLI flags and configuration options are properly documented and validated via `settings.toml.example`
8. ✅ Application handles edge cases (invalid targets, CIDR ranges, malformed configs) without crashing
9. ✅ Security-sensitive operations sanitize inputs and avoid command injection vulnerabilities
10. ✅ Audit logs include `CHAIN`-tagged events for every adaptive decision, enabling full traceability
11. ✅ License (MIT) and disclaimer remain visible and unmodified in all distributions

## Gap list

Each gap between current state and production-ready definition, ordered in build order:

1. **TUI report-directory propagation — corrected locally by E17/21** (S)
   - File: `src/main.rs`
   - The CLI option is passed to `run_tui()`, resolved against the configured default once, and cloned into both scanner start paths. Local option tests cover explicit and omitted values; live TUI scanning remains outside this verification.

2. **CLI version consistency — corrected locally by E17/21** (S)
   - File: `src/main.rs`
   - Clap derives `--version` from Cargo package metadata; a pure parser test checks the displayed version.

3. **No integration tests with real protocol services** (M)
   - Files: `tests/`, `src/core/test_*.rs`
   - No standing HTTP/FTP/SMB services in CI for integration testing. Current tests are all unit-level mocks. Medium gap — would require standing test infrastructure.

4. **No CI/CD pipeline configuration** (M)
   - Files: `.github/workflows/`, `Makefile`
   - No GitHub Actions or Makefile targets for automated testing, building, or release packaging. Medium gap — adds pipeline configuration.

5. **No formal release artifact packaging (deb/rpm/tar.gz)** (M)
   - Files: `Cargo.toml`, `scripts/`
   - No defined packaging workflow. Current distribution is source-only via cargo. Medium gap — define packaging process.

6. **No SBOM or automated dependency scanning** (S)
   - Files: `Cargo.toml`, `scripts/`
   - No supply-chain transparency tooling (cyclonedx, cargo-deny). Small gap — add dependency scanning script.

7. **TUI report-directory propagation — duplicate of gap #1** (S)
   - Covered by the same E17/21 correction; no separate implementation task.

## NBR-OS relationship

- **Uses**: None — Sentinel operates independently; all data local to the application
- **Should use (opt-in)**: Auth (for session sync across workstations), Telemetry (opt-in usage stats), Commerce Billing (if monetized later)
- **Deliberately avoids**: Design tokens (TUI is self-contained, no external design system), centralized config (local `settings.toml` preferred over NBR-OS config store)

## Decisions needed

- Should Sentinel integrate with NBR-OS auth and telemetry on an opt-in basis? Define the mechanism if yes.
- Should Docker mode require internet access, or should offline fallback be enforced as a build-time flag?
- Should CI/CD pipelines (GitHub Actions) be added for automated testing and release packaging?
- Should integration test infrastructure (standing services) be added to the repository?