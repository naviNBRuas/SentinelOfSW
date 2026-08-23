# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/) —
pre-1.0, so the minor version (`0.x.0`) carries new functionality and the
patch version (`0.0.x`) carries fixes, per [CONTRIBUTING.md](CONTRIBUTING.md).

## [Unreleased]

## [0.1.0] — 2026

Initial public release.

### Added

- Nine scanner modules: port scanner (async TCP, banner grabbing, OS
  detection), DNS recon (subdomains, SRV/CAA/DNSSEC), web enumeration
  (directory brute-force, tech detection, security headers, WebSocket,
  TLS), SMB enumeration (null session, share TreeConnect, signing checks),
  credential checker (default creds, SMTP/POP3/IMAP auth, Hydra), exploit
  hunter (per-port CVE matching), privilege escalation strategy, OSINT
  recon (crt.sh, DNS records, WHOIS), and network discovery (ping,
  traceroute).
- Seven workflow modes: Beginner, Professional, CTF, Quick, Stealth,
  ReconOnly, and Full.
- Adaptive orchestration engine — a deterministic, fully-auditable trigger
  system that reacts to in-scan discoveries (credential reuse validation,
  secret-harvest → credential-pool chaining) and schedules bounded
  follow-up work.
- Cross-module attack-path correlation engine with confidence-weighted
  scoring.
- Educational layer: every finding carries "What", "Why", "How",
  "Mitigation", and "References".
- Report generation in Markdown, HTML, JSON, YAML, and plain-text summary.
- Interactive Ratatui TUI and a headless CLI mode for automation/CI.
- Optional Docker-backed tool execution against a Kali Linux container
  (12+ industry-standard tools), with graceful fallback to built-in
  scanners when unreachable.
- OpenVPN/WireGuard session management via `--vpn`.
- SQLite-backed session history (`--history`, `--history-id`).
- `settings.toml` configuration for ports, timeouts, concurrency,
  wordlists, and proxy settings.

[Unreleased]: https://github.com/naviNBRuas/SentinelOfSW/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/naviNBRuas/SentinelOfSW/releases/tag/v0.1.0
