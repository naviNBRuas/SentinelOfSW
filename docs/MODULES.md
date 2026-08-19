# Sentinel Modules — Detailed Reference

## Overview

Sentinel has 9 modules, each implementing the `Module` trait. Modules are registered in `ModuleRegistry::build_default()` and dispatched by the two-phase execution system.

---

## 1. DNS Reconnaissance (`recon`)

**File:** `src/modules/recon.rs`

Discovers DNS records and enumerates subdomains for domain targets.

### Capabilities
- **Subdomain Enumeration**: Checks 316 common subdomain names via A record lookups
- **SRV Records**: Enumerates 20+ service types (_http._tcp, _ldap._tcp, _sip._tls, etc.)
- **CAA Records**: Certificate Authority Authorization policy
- **DNSSEC**: Detects DNSKEY records indicating DNSSEC signing
- **Zone Transfer**: Attempts AXFR request (rarely succeeds externally, critical if it does)
- **Subdomain Permutations**: Generates dev/staging/backup permutations from discovered subdomains
- **IP Detection**: Skips subdomain enumeration when target is IP address (avoids wasted DNS lookups)

### Confidence Levels
- Subdomain hits, AXFR success: 0.95
- SRV/CAA/DNSSEC records: 0.9
- Permutation discoveries: 0.85
- Completion/skip messages: 1.0

---

## 2. Port Scanner (`port_scan`)

**File:** `src/modules/port_scanner.rs`

Async TCP port scanner with service identification and OS fingerprinting.

### Capabilities
- **Async TCP Connect**: Uses `tokio::task::spawn_blocking` + `TcpStream::connect_timeout` for non-blocking concurrent scanning
- **Nmap Integration**: Falls through to nmap via Docker when available
- **Banner Grabbing**: Captures service banners from open ports
- **OS Detection**: Classifies OS from TCP TTL values:
  - TTL=64 → Linux/Unix (0.85 confidence)
  - TTL=128 → Windows (0.85 confidence)
  - TTL=255 → Solaris/Cisco (0.85 confidence)
  - Other values → fuzzy match with lower confidence
- **Service Version Extraction**: Parses banners for version strings (OpenSSH, Apache, nginx, IIS, ProFTPD, vsFTPd, MySQL, PostgreSQL, Redis)
- **Port Sets**: Configurable per-mode via `settings.toml`:
  - Beginner/Professional: ~170 ports
  - CTF: ~6500 ports (ranges + specific)
  - Quick: 31 common ports

### Confidence Levels
- nmap detection: 0.98
- TCP connect: 0.95
- OS fingerprint (exact TTL match): 0.85
- OS fingerprint (range TTL): 0.6

---

## 3. Web Enumeration (`web`)

**File:** `src/modules/web.rs`

HTTP service enumeration with technology detection and vulnerability mapping.

### Capabilities
- **Directory Brute-force**: 110+ common paths (admin, backup, config, etc.)
- **CTF File Search**: 30+ CTF patterns (flag.txt, .git/config, backup.sql, shell scripts)
- **Technology Detection**: Server header, X-Powered-By, Set-Cookie analysis
- **Security Headers**: Checks 8 common headers (X-Frame-Options, CSP, HSTS, etc.)
- **WebSocket Detection**: Checks for Upgrade: websocket header
- **TLS Certificate Analysis**: sslscan via Docker for HTTPS services
- **CMS Fingerprinting**: Detects WordPress, Drupal, Joomla via body markers
- **Nikto Integration**: Web server vulnerability scanning via Docker
- **ffuf Integration**: Directory fuzzing via Docker

### Confidence Levels
- Flag found (regex match): 1.0
- robots.txt, server detection: 0.95
- Path discovery, security headers, TLS: 0.9
- ffuf discovery: 0.85
- WebSocket detection: 0.8
- CMS fingerprint, Nikto findings: 0.7

---

## 4. SMB Enumeration (`smb`)

**File:** `src/modules/smb.rs`

Windows SMB/CIFS service enumeration using raw protocol packets.

### Capabilities
- **SMBv2/v3 Negotiate**: Sends raw SMB negotiate request, parses response to detect dialect version (2.0.2, 2.1, 3.0, 3.1.1)
- **Null Session Detection**: Attempts SessionSetup with null/empty security blob — success indicates anonymous access
- **Signing Checks**: Detects whether SMB signing is required or disabled
- **Share Enumeration**: Probes 20 common share names via TreeConnect request (ADMIN$, C$, IPC$, SYSVOL, NETLOGON, etc.)
- **enum4linux-ng Integration**: Via Docker
- **smbmap Integration**: Via Docker

### Confidence Levels
- Service detected/not detected: 1.0
- SMB signing disabled, null session, old version: 0.95
- SMB signing required, accessible shares: 0.9
- enum4linux output: 0.85
- Connection timeout: 0.8
- Unrecognized service: 0.5

---

## 5. Credential Checker (`creds`)

**File:** `src/modules/creds.rs`

Tests for default and weak credentials on common services.

### Capabilities
- **Default Credential Database**: 7 service types (FTP, SSH, HTTP, MySQL, PostgreSQL, Redis, SMB)
- **FTP Authentication**: Real USER/PASS command sequence
- **SSH Banner Check**: Extracts SSH version for vulnerability mapping
- **HTTP Header Analysis**: Checks for WWW-Authenticate headers
- **SMTP Authentication**: RAW AUTH LOGIN command (base64-encoded)
- **POP3 Authentication**: RAW USER/PASS command sequence
- **IMAP Authentication**: RAW LOGIN command (base64-encoded)
- **Hydra Integration**: Online password brute-forcing via Docker

### Confidence Levels
- hydra success: 0.95
- Manual `try_login()` success: 0.9

---

## 6. Exploit Hunter (`exploit`)

**File:** `src/modules/exploit.rs`

Maps open ports to known vulnerabilities and exploits.

### Capabilities
- **Per-Port CVE Tables**: Targeted CVE suggestions for each service:
  - Port 22 (SSH): CVE-2024-6387 (regreSSHion), CVE-2018-15473 (user enum)
  - Port 21 (FTP): CVE-2021-3007 (Zoo Management), CVE-2019-12815 (ProFTPD)
  - Port 80/443 (HTTP): CVE-2021-41773 (Apache path traversal), CVE-2017-7269 (IIS)
  - Port 445 (SMB): CVE-2017-0144 (EternalBlue), CVE-2020-0796 (SMBGhost)
  - Port 3389 (RDP): CVE-2019-0708 (BlueKeep), CVE-2020-0609 (RDP MITM)
  - Port 6379 (Redis): CVE-2022-0543 (sandbox escape), CVE-2021-32762
  - Port 2375/2376 (Docker): CVE-2024-21626 (runC escape)
  - Port 6443/10250 (K8s): API server, kubelet unauthenticated access
  - Port 1433 (MSSQL): CVE-2024-35272 (SQL injection)
  - Port 3306 (MySQL): CVE-2012-2122 (auth bypass)
  - Port 5432 (PostgreSQL): CVE-2024-0196 (MITM), CVE-2024-0985 (late auth)
  - Port 2049 (NFS): CVE-2023-32721 (privileged NFS export)
  - Port 5900/5901 (VNC): CVE-2006-2369 (auth bypass)
  - Port 11211 (Memcached): CVE-2023-28327 (statistics leak)
  - Port 9200 (Elasticsearch): CVE-2023-31418 (remote code execution)
  - Port 27017 (MongoDB): CVE-2024-1354 (auth bypass)
  - Port 6000 (X11): CVE-2024-31080 (session hijacking)
- **CTF-Specific Attack Vectors**: Web, SQL injection, FTP, NFS privilege escalation, SSH

### Confidence Levels
- Docker REST API (2375): 0.95
- Telnet: 0.9
- SMB, K8s, Memcached: 0.8
- Redis CVE, CTF targets: 0.75
- MSRPC, LDAP, MySQL, VNC, etc.: 0.7
- Generic CVE (port-based, no version): 0.6
- POP3, IMAP, DNS: 0.5

---

## 7. Privilege Escalation (`priv_esc`)

**File:** `src/modules/priv_esc.rs`

Generates privilege escalation strategy based on detected services.

### Capabilities
- **Linux PE Checklist**: 10-point checklist (kernel exploits, SUID, sudo -l, writable passwd, cron, Docker socket, capabilities, NFS, LXC/LXD)
- **Windows PE Checklist**: 10-point checklist (token privileges, systeminfo, installed software, service permissions, weak ACLs, registry, admin group, scheduled tasks, WinPEAS, PowerUp)
- **CTF Quick Commands**: Pre-built PE command lists for CTF scenarios
- **Docker Container Escape**: docker -H tcp://... run -v /:/mnt
- **Kubernetes API Access**: kubelet API, dashboard, service account tokens
- **NFS Root Squashing**: no_root_squash privilege escalation

### Confidence Levels
- Docker escape (2375/2376): 0.95
- CTF Linux commands: 0.9
- Linux/Win PE strategy, K8s access: 0.8
- NFS root squashing: 0.7
- No automated targets: 0.5

---

## 8. OSINT Reconnaissance (`osint`)

**File:** `src/modules/osint.rs`

Passive open-source intelligence gathering.

### Capabilities
- **Certificate Transparency**: crt.sh API queries for historical subdomains
- **MX Records**: Mail exchanger discovery
- **NS Records**: Nameserver identification
- **PTR Records**: Reverse DNS lookup
- **TXT/SPF/DKIM Records**: Email security policy and domain verification
- **Subdomain Brute-force**: Dictionary-based subdomain resolution
- **WHOIS**: Domain registration information (via Docker or system whois)

### Confidence Levels
- MX, NS, subdomain hits: 0.95
- PTR, TXT/SPF/DKIM: 0.9
- crt.sh results: 0.85

---

## 9. Network Discovery (`network_discovery`)

**File:** `src/modules/network_discovery.rs`

Active network reconnaissance using system tools.

### Capabilities
- **ICMP Ping Sweep**: Uses system `ping -c 1 -W 2` to check host reachability (5-second timeout)
- **Traceroute**: Uses system `traceroute -n -m 15` to map network path (30-second timeout)
- **Network Proximity Assessment**: Correlates open port count with host reachability

### Confidence Levels
- Ping success: 0.95
- Traceroute hops discovered: 0.9
- Proximity assessment: 0.8
- No ping response: 0.6
- Tool failure: 0.5

---

## Module Integration

Modules are dispatched through a two-phase pipeline:

```
Phase 1 (unconditional):
  [recon] → [port_scan]
       ↓
Phase 2 (regenerated plan with discovered ports):
  [network_discovery] → [web] → [smb] → [creds] → [exploit] → [priv_esc] → [osint]
       ↓
Attack Path Generation:
  CorrelationEngine + Orchestrator → prioritized attack paths
       ↓
Report Generation:
  EvidenceManager → summary.txt, report.md, report.html, report.json, report.yaml
       ↓
Session Persistence:
  SessionDb → sentinel_history.db
```

All modules run asynchronously via `tokio::spawn`, communicating findings back through `Arc<Mutex<WorkflowOrchestrator>>` shared state.
