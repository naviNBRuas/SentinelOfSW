# Sentinel — Repository Audit Report

*Audit date: 2026-08-24 · Scope: README, CHANGELOG, docs/ (ROADMAP, MODULES,
CONFIGURATION), full src/ tree (~10.5k lines Rust), CI/config files.*

## Current Maturity

Sentinel is a real, working pre-1.0 product rather than a skeleton: all nine
scanner modules, all seven workflow modes, the adaptive orchestration engine
(bounded credential-reuse and secret-harvest chains with `max_rounds = 3` and a
global follow-up cap), the cross-module correlation engine, the Ratatui TUI,
headless/JSON mode, five-format report generation, SQLite session history, VPN
lifecycle management, and Docker-backed Kali tooling are implemented end-to-end
and wired through `run_scanner` in `src/main.rs`. The codebase carries 130+
unit tests concentrated in the core logic (findings, target parsing,
correlation, workflow planning, evidence generation, orchestrator), and its
documentation is unusually complete for this stage — README, per-module
reference, configuration reference, roadmap, changelog, and community health
files are all present and internally consistent. Maturity is best described as
"feature-complete prototype, hardening phase": the architecture is sound and
the happy paths work, but the project has only two commits of history, no
continuous integration despite the test suite, unit-level test coverage only,
small bundled wordlists, and several CLI/TUI rough edges (below). It is solidly
usable today in CTF/lab contexts; production readiness hinges on the gaps
listed next rather than on missing core functionality.

## Top 5 Gaps to Complete / Feature-Rich / Production-Ready

- **No CI pipeline.** `.github/` contains only `FUNDING.yml`; there is no
  workflow that builds the crate or runs the existing 130+ tests, so regressions
  land undetected. A minimal build + `cargo test` + clippy + fmt workflow is the
  single highest-leverage addition.
- **No scan resume / interrupted-scan recovery.** Session history is
  write-then-view (`--history`, `--history-id`); a killed CIDR sweep restarts
  from zero. `--resume` is acknowledged as planned in docs/ROADMAP.md and marked
  "future" in README.
- **Wordlists are toy-scale.** Bundled lists total 780 lines
  (`wordlists/*.txt`: 133–316 lines each), far below real-world coverage;
  subdomain and directory enumeration silently underperform against any
  hardened target. The roadmap's "bundled wordlists / fetch on first use" item
  should ship before calling web/DNS recon feature-complete.
- **Integration testing infrastructure absent.** All tests are unit-level
  mocks; nothing exercises live HTTP/FTP/SMB protocol behavior (also flagged in
  the roadmap). Production readiness requires standing test services plus
  end-to-end headless runs asserting on JSON/report output.
- **Operational hardening gaps:** release packaging (no tagged binaries,
  container image, or install path beyond `cargo build`); `reqwest` depends on
  system OpenSSL headers (no rustls/static-build option); Docker-mode behavior
  is untested against absent/partial daemon states; no benchmarking for the
  large-CIDR concurrency path the roadmap itself calls out as untuned.

## Bugs and Unfinished Items Noticed While Skimming

- **Version string contradiction:** `src/main.rs:31` hardcodes clap
  `version = "2.0"` while `Cargo.toml` declares `0.1.0` and the CHANGELOG
  documents only 0.1.0. `sentinel --version` reports a version that does not
  exist anywhere else. Should use `env!("CARGO_PKG_VERSION")`.
- **TUI ignores `--output-dir`:** the flag is only forwarded to
  `run_headless` (`src/main.rs:324`); both TUI launch paths use
  `Settings::global().report_path()` directly (`src/main.rs:578`, `665`),
  silently writing reports elsewhere when the flag is set in TUI mode.
- **VPN is lifecycle-only:** `run_headless` receives `_vpn:
  Option<Arc<VpnManager>>` and drops it (`src/main.rs:432`); routing correctness
  relies entirely on OS-level interface defaults, and per-host scans never
  re-check VPN health between hosts in a CIDR loop.
- **Session timestamps are fake precision:** `SessionDb::save` sets
  `started_at` and `completed_at` to the same `Utc::now()` call
  (`src/core/session.rs:63-64`), so recorded scan durations are always zero.
- **README promises a feature that doesn't exist yet** ("Re-run from session
  data (future: --resume)") — honest, but it is an unfinished surface visible to
  users.
- Minor: severity summaries index raw arrays by position (`counts[4]`,
  `src/main.rs:359-363`) — brittle if severity ordering ever changes; `unwrap()`
  density is highest in `src/main.rs` (16 sites) where lock poisoning would
  panic instead of degrading gracefully.

## Verdict

Strong foundation, credible scope discipline (exploitation explicitly out of
scope), and documentation quality above average for a v0.1. Priority order to
"production-ready": CI first, then wordlist scale-up, resume support,
integration-test services, and finally packaging/hardening.
