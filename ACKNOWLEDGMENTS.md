# Acknowledgments

Sentinel is built in Rust on the shoulders of a small number of excellent
crates. Particular thanks to the maintainers of:

- [Ratatui](https://github.com/ratatui-org/ratatui) and
  [Crossterm](https://github.com/crossterm-rs/crossterm) — the terminal UI
  and backend that power Sentinel's interactive TUI.
- [Tokio](https://tokio.rs) — the async runtime underneath every scanner
  module and the orchestration engine.
- [petgraph](https://github.com/petgraph/petgraph) — graph processing used
  by the workflow/attack-path engine.
- [Clap](https://github.com/clap-rs/clap) — CLI argument parsing.
- [sqlx](https://github.com/launchbadge/sqlx) — the SQLite session-history
  backend.
- [reqwest](https://github.com/seanmonstar/reqwest) and
  [hickory-resolver](https://github.com/hickory-dns/hickory-dns) — HTTP and
  DNS resolution used across the web, OSINT, and recon modules.
- [serde](https://serde.rs) and the wider Serde ecosystem
  (`serde_json`, `serde_yaml`, `toml`) — every config and report format
  Sentinel reads or writes.
- The [Kali Linux](https://www.kali.org) project — the container image
  Sentinel's optional Docker tool-execution mode pulls its industry-standard
  tooling (`nmap`, `ffuf`, `nikto`, `hydra`, `gobuster`, `enum4linux-ng`,
  `smbmap`, `searchsploit`, `sslscan`, `dnsrecon`, `whois`) from.

And to the broader offensive-security community whose public writeups,
CVE research, and enumeration methodology informed the educational
"What/Why/How/Mitigation/References" content baked into every finding.

See [CONTRIBUTORS.md](CONTRIBUTORS.md) for people who have contributed code
directly to this repository.
