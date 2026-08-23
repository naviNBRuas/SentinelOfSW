# Configuration Reference

Sentinel reads an optional `settings.toml` from the working directory. Copy
the example to get started:

```bash
cp settings.toml.example settings.toml
```

Every value has a built-in default — omit any section (or the whole file)
and Sentinel falls back to those defaults. This file documents each section
in [`settings.toml.example`](../settings.toml.example).

## `[ports]`

Per-mode port lists, consumed by the port scanner module.

| Key | Type | Used by | Default size |
|---|---|---|---|
| `default` | array of ints | Beginner / Professional modes | ~170 ports |
| `ctf` | array of ints and `{start, end}` ranges | CTF mode | ~6500 ports |
| `quick` | array of ints | Quick mode | 31 ports |

Ranges are written as inline tables: `{start = 1, end = 1024}`.

## `[timeouts]`

All values in the units named by the key.

| Key | Meaning |
|---|---|
| `connect_ms` | TCP connect timeout for the port scanner (non-CTF modes) |
| `ctf_connect_ms` | TCP connect timeout in CTF mode (lower — more ports, less patience per port) |
| `http_secs` | HTTP request timeout (web/OSINT modules) |
| `dns_secs` | DNS lookup timeout (recon/OSINT modules) |
| `banner_secs` | Banner-grab read timeout (port scanner) |

## `[concurrency]`

Batch/semaphore sizes bounding how many probes run in parallel per module.

| Key | Meaning |
|---|---|
| `port_scan_batch` | Concurrent port-scan tasks, non-CTF modes |
| `port_scan_ctf_batch` | Concurrent port-scan tasks, CTF mode |
| `dns_semaphore` | Concurrent DNS lookups (recon module) |
| `web_semaphore` | Concurrent HTTP requests (web module) |

Raising these speeds up scans at the cost of being louder/more likely to
trip rate limiting or IDS — see the README's Stealth mode for the opposite
tradeoff.

## `[scan]`

| Key | Meaning |
|---|---|
| `report_path` | Base directory reports are written under (see README's "Reports" section) |
| `user_agent` | User-Agent sent by the web module |
| `osint_user_agent` | User-Agent sent by the OSINT module (kept separate so it's identifiable as recon, not a browsing spoof) |
| `proxy_url` | HTTP proxy for web/OSINT requests (e.g. `http://127.0.0.1:8080` for Burp/ZAP). Empty uses the system proxy or connects directly; `reqwest` also honors `HTTP_PROXY`/`HTTPS_PROXY` env vars |
| `wordlist_subdomains_file` | Path to an external subdomain wordlist. Empty (or missing file) falls back to the built-in list in `wordlists/subdomains.txt` |
| `wordlist_directories_file` | Same, for web directory brute-force (`wordlists/directories.txt`) |
| `wordlist_ctf_files_file` | Same, for CTF file-hunting patterns (`wordlists/ctf_files.txt`) |

## Environment variables

- `HTTP_PROXY` / `HTTPS_PROXY` — honored by `reqwest` directly; `proxy_url`
  above takes precedence when set.

## VPN configs

Not part of `settings.toml`. Place `.ovpn` (OpenVPN) or `.conf` (WireGuard)
files directly in `./vpn/` and reference them by filename with `--vpn
<name>` — see the README's "VPN Management" section.
