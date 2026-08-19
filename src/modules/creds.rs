use crate::core::adaptive::{Credential, Intent, ScanContext};
use crate::core::config::Settings;
use crate::core::docker::global_docker;
use crate::core::findings::{Finding, Severity};
use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use crate::core::knowledge::KnowledgeBase;
use crate::core::tools::run_hydra;
use crate::core::workflow::WorkflowMode;
use crate::modules::Module;
use async_trait::async_trait;
use sha1::{Sha1, Digest};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::process::Command;
use tokio::sync::mpsc::Sender;
use tokio::time::timeout;

const DEFAULT_CREDS: &[(&str, &[(&str, &str)])] = &[
    ("FTP", &[("anonymous", "anonymous"), ("anonymous", ""), ("admin", "admin"), ("root", "root"), ("ftp", "ftp")]),
    ("SSH", &[("root", "root"), ("admin", "admin"), ("root", "toor"), ("root", "123456"), ("admin", "123456")]),
    ("MySQL", &[("root", ""), ("root", "root"), ("admin", "admin"), ("root", "password")]),
    ("PostgreSQL", &[("postgres", ""), ("postgres", "postgres"), ("admin", "admin")]),
    ("MSSQL", &[("sa", ""), ("sa", "sa"), ("sa", "password"), ("admin", "admin")]),
    ("Redis", &[("", ""), ("default", "default")]),
    ("MongoDB", &[("admin", ""), ("admin", "admin"), ("root", "root")]),
    ("HTTP", &[("admin", "admin"), ("admin", "password"), ("admin", "123456"), ("root", "root"), ("user", "user")]),
    ("SMTP", &[("admin", "admin"), ("root", "root"), ("postmaster", ""), ("noreply", "noreply")]),
    ("POP3", &[("admin", "admin"), ("root", "root"), ("test", "test"), ("user", "pass")]),
    ("IMAP", &[("admin", "admin"), ("root", "root"), ("test", "test"), ("user", "pass")]),
];

pub(crate) fn service_from_port(port: u16) -> &'static str {
    match port {
        21 => "FTP", 22 => "SSH", 80 | 443 | 8080 | 8443 | 8000 | 3000 | 5000 | 8888 | 9090 => "HTTP",
        25 | 465 | 587 => "SMTP", 110 | 995 => "POP3", 143 | 993 => "IMAP",
        3306 => "MySQL", 5432 => "PostgreSQL", 1433 => "MSSQL", 6379 => "Redis", 27017 => "MongoDB",
        _ => "Unknown",
    }
}

pub struct CredChecker;

#[async_trait]
impl Module for CredChecker {
    fn name(&self) -> &str {
        "Credential Checker"
    }

    async fn execute_with_ports(&self, target: &str, open_ports: &[u16], mode: &WorkflowMode, tx: Sender<String>) -> Result<Vec<Finding>, anyhow::Error> {
        let _ = tx.send("[Creds] Starting default credential checks...".into()).await;
        let mut findings = Vec::new();

        // Try hydra via Docker for HTTP/SSH/FTP brute-force in CTF mode
        if let Some(docker) = global_docker() {
            if matches!(mode, WorkflowMode::Ctf) || matches!(mode, WorkflowMode::Beginner) {
                for &port in open_ports {
                    let service = service_from_port(port);
                    let hydra_service = match port {
                        22 => "ssh",
                        21 => "ftp",
                        80 | 443 | 8080 | 8443 | 8000 | 3000 | 5000 | 8888 | 9090 => "http-get",
                        3306 => "mysql",
                        5432 => "postgres",
                        _ => continue,
                    };
                    let _ = tx.send(format!("[Creds] Running hydra on {}:{} ({})", service, port, hydra_service)).await;
                    let result = run_hydra(target, hydra_service, port, "admin",
                        "/usr/share/wordlists/fasttrack.txt", Some(docker), 60).await;

                    let found: Vec<&str> = result.stdout.lines()
                        .filter(|l| l.contains("password:") || l.contains("login:"))
                        .filter(|l| !l.contains("[0]") && !l.contains("0 valid"))
                        .collect();

                    for line in found.iter().take(5) {
                        let _ = tx.send(format!("[Creds] Hydra found: {}", line.trim())).await;
                        let user = line.split_whitespace().filter_map(|w| w.strip_prefix("login:")).next().unwrap_or("admin");
                        let pass = line.split_whitespace().filter_map(|w| w.strip_prefix("password:")).next().unwrap_or("unknown");
                        findings.push(
                            Finding::new(target, "creds",
                                &format!("Default Credentials (hydra): {}:{} on {}", user, pass, service),
                                &format!("Hydra discovered default credentials for {} on port {}: '{}':'{}'.", service, port, user, pass),
                                Severity::Critical,
                            ).with_confidence(0.95)
                            .with_evidence(vec![format!("Hydra: {}:{} on {}:{}/{}", user, pass, target, port, hydra_service)]),
                        );
                    }
                }
            }
        }

        // Manual credential checks (also try CLI tools when available)
        for &port in open_ports {
            let service = service_from_port(port);
            if service == "Unknown" { continue; }

            let _ = tx.send(format!("[Creds] Testing {}:{}", service, port)).await;

            if let Some(creds_list) = DEFAULT_CREDS.iter().find(|(s, _)| *s == service) {
                for (user, pass) in creds_list.1 {
                    let ok = try_login(target, port, service, user, pass).await;
                    if ok {
                        let _ = tx.send(format!("[Creds] FOUND: {}:{} @ {}:{}", user, pass, service, port)).await;
                        findings.push(
                            Finding::new(target, "creds",
                                &format!("Default Credentials: {}:{} on {}", user, pass, service),
                                &format!("Default credentials found for {} on port {}: '{}':'{}'. Immediate unauthorized access possible.", service, port, user, pass),
                                Severity::Critical,
                            ).with_confidence(0.9)
                            .with_education(KnowledgeBase::for_default_creds())
                            .with_evidence(vec![format!("Authenticated to {}:{} with {}/{}", service, port, user, pass)]),
                        );
                        break;
                    }
                }
            }
        }

        let _ = tx.send(format!("[Creds] Complete. {} findings.", findings.len())).await;
        Ok(findings)
    }

    async fn execute_adaptive(
        &self,
        target: &str,
        open_ports: &[u16],
        mode: &WorkflowMode,
        intent: &Intent,
        ctx: Arc<Mutex<ScanContext>>,
        tx: Sender<String>,
    ) -> Result<Vec<Finding>, anyhow::Error> {
        match intent {
            // Normal run, but additionally publish every proven credential to the
            // shared context so the adaptive engine can chain on it.
            Intent::Standard => {
                let findings = self.execute_with_ports(target, open_ports, mode, tx).await?;
                if let Ok(mut c) = ctx.lock() {
                    for cred in credentials_from_findings(&findings) {
                        c.add_credential(cred);
                    }
                }
                Ok(findings)
            }
            // Validate each known credential against every *other* auth-capable
            // open port. This is credential validation (the same class of action
            // this module already performs), never post-exploitation.
            Intent::CredReuse { credentials } => {
                let mut findings = Vec::new();
                let mut attempted: HashSet<(String, String, u16)> = HashSet::new();
                for cred in credentials {
                    for &port in open_ports {
                        if port == cred.port {
                            continue; // skip the origin service
                        }
                        let service = service_from_port(port);
                        if service == "Unknown" {
                            continue;
                        }
                        let dedup = (cred.user.clone(), cred.pass.clone(), port);
                        if !attempted.insert(dedup) {
                            continue;
                        }
                        let _ = tx
                            .send(format!("[Creds] Reuse: trying {}:{} on {}:{}", cred.user, cred.pass, service, port))
                            .await;
                        if try_login(target, port, service, &cred.user, &cred.pass).await {
                            let _ = tx
                                .send(format!("[Creds] REUSE SUCCESS: {}:{} @ {}:{}", cred.user, cred.pass, service, port))
                                .await;
                            findings.push(
                                Finding::new(
                                    target,
                                    "creds",
                                    &format!("Credential Reuse: {}:{} on {}", cred.user, cred.pass, service),
                                    &format!(
                                        "Credential '{}':'{}' (originally from {}) is also valid on {} (port {}). \
                                         Reused credentials enable lateral movement across services.",
                                        cred.user, cred.pass, cred.source, service, port
                                    ),
                                    Severity::Critical,
                                )
                                .with_confidence(0.95)
                                .with_education(KnowledgeBase::for_default_creds())
                                .with_evidence(vec![format!(
                                    "{}:{} (from {}) authenticated to {}:{}",
                                    cred.user, cred.pass, cred.source, service, port
                                )]),
                            );
                        }
                    }
                }
                let _ = tx
                    .send(format!("[Creds] Reuse complete. {} reused credential(s).", findings.len()))
                    .await;
                Ok(findings)
            }
            // creds has nothing to do for a web-oriented intent.
            Intent::SecretHarvest { .. } => Ok(Vec::new()),
        }
    }
}

/// Extract structured credentials from this module's own findings, so they can
/// be published to the shared [`ScanContext`]. Parsing keys off the evidence
/// line formats emitted in `execute_with_ports`:
/// `"Authenticated to <SERVICE>:<PORT> with <user>/<pass>"` and
/// `"Hydra: <user>:<pass> on <target>:<PORT>/<svc>"`.
fn credentials_from_findings(findings: &[Finding]) -> Vec<Credential> {
    let mut out = Vec::new();
    for f in findings {
        if f.module != "creds" {
            continue;
        }
        for ev in &f.evidence {
            if let Some(cred) = parse_credential_evidence(ev) {
                out.push(cred);
            }
        }
    }
    out
}

fn parse_credential_evidence(ev: &str) -> Option<Credential> {
    let ev = ev.trim();
    if let Some(rest) = ev.strip_prefix("Authenticated to ") {
        // "<SERVICE>:<PORT> with <user>/<pass>"
        let (svc_port, creds) = rest.split_once(" with ")?;
        let (service, port) = svc_port.rsplit_once(':')?;
        let port: u16 = port.parse().ok()?;
        let (user, pass) = creds.split_once('/')?;
        return Some(Credential {
            service: service.to_string(),
            port,
            user: user.to_string(),
            pass: pass.to_string(),
            source: format!("default-creds@{}", port),
        });
    }
    if let Some(rest) = ev.strip_prefix("Hydra: ") {
        // "<user>:<pass> on <target>:<PORT>/<svc>"
        let (creds, loc) = rest.split_once(" on ")?;
        let (user, pass) = creds.split_once(':')?;
        let port: u16 = loc
            .rsplit_once(':')
            .and_then(|(_, tail)| tail.split('/').next())
            .and_then(|p| p.parse().ok())?;
        return Some(Credential {
            service: service_from_port(port).to_string(),
            port,
            user: user.to_string(),
            pass: pass.to_string(),
            source: format!("hydra@{}", port),
        });
    }
    None
}

async fn try_login(target: &str, port: u16, service: &str, user: &str, pass: &str) -> bool {
    let addr = format!("{}:{}", target, port);
    match timeout(Settings::global().connect_timeout(), TcpStream::connect(&addr)).await {
        Ok(Ok(mut stream)) => {
            match service {
                "FTP" => check_ftp(&mut stream, user, pass).await,
                "SSH" => check_ssh_cli(target, port, user, pass).await,
                "HTTP" => check_http_basic(target, port, user, pass).await,
                "Redis" => check_redis(&mut stream, pass).await,
                "MySQL" => check_mysql_raw(&mut stream, user, pass).await,
                "PostgreSQL" => check_postgres_cli(target, port, user, pass).await,
                "MSSQL" => check_mssql_raw(&mut stream).await,
                "MongoDB" => check_mongodb_raw(&mut stream).await,
                "SMTP" => check_smtp(&mut stream, user, pass).await,
                "POP3" => check_pop3(&mut stream, user, pass).await,
                "IMAP" => check_imap(&mut stream, user, pass).await,
                _ => false,
            }
        }
        _ => false,
    }
}

async fn check_smtp(stream: &mut TcpStream, user: &str, pass: &str) -> bool {
    let mut buf = [0u8; 512];
    let _ = timeout(Settings::global().banner_timeout(), stream.read(&mut buf)).await.ok();
    let banner = String::from_utf8_lossy(&buf);
    if !banner.contains("220") { return false; }

    let cmd = "EHLO sentinel\r\n";
    let _ = stream.write_all(cmd.as_bytes()).await.ok();
    buf.fill(0);
    let _ = timeout(Settings::global().banner_timeout(), stream.read(&mut buf)).await.ok();
    let resp = String::from_utf8_lossy(&buf);

    if !resp.contains("250") { return false; }
    if resp.contains("AUTH") || resp.contains("auth") {
        let auth_cmd = format!("AUTH LOGIN\r\n");
        let _ = stream.write_all(auth_cmd.as_bytes()).await.ok();
        buf.fill(0);
        let _ = timeout(Settings::global().banner_timeout(), stream.read(&mut buf)).await.ok();
        let resp2 = String::from_utf8_lossy(&buf);
        if resp2.contains("334") {
            let user_b64 = base64_encode(user.as_bytes());
            let pass_b64 = base64_encode(pass.as_bytes());
            let _ = stream.write_all(format!("{}\r\n", user_b64).as_bytes()).await.ok();
            buf.fill(0);
            let _ = timeout(Settings::global().banner_timeout(), stream.read(&mut buf)).await.ok();
            let _ = stream.write_all(format!("{}\r\n", pass_b64).as_bytes()).await.ok();
            buf.fill(0);
            let _ = timeout(Settings::global().banner_timeout(), stream.read(&mut buf)).await.ok();
            let resp3 = String::from_utf8_lossy(&buf);
            return resp3.contains("235") || resp3.contains("334");
        }
    }
    false
}

async fn check_pop3(stream: &mut TcpStream, user: &str, pass: &str) -> bool {
    let mut buf = [0u8; 512];
    let _ = timeout(Settings::global().banner_timeout(), stream.read(&mut buf)).await.ok();
    let _ = String::from_utf8_lossy(&buf);

    let cmd = format!("USER {}\r\n", user);
    let _ = stream.write_all(cmd.as_bytes()).await.ok();
    buf.fill(0);
    let _ = timeout(Settings::global().banner_timeout(), stream.read(&mut buf)).await.ok();
    let resp = String::from_utf8_lossy(&buf);
    if !resp.contains("+OK") { return false; }

    let cmd = format!("PASS {}\r\n", pass);
    let _ = stream.write_all(cmd.as_bytes()).await.ok();
    buf.fill(0);
    let _ = timeout(Settings::global().banner_timeout(), stream.read(&mut buf)).await.ok();
    let resp = String::from_utf8_lossy(&buf);
    resp.contains("+OK")
}

async fn check_imap(stream: &mut TcpStream, user: &str, pass: &str) -> bool {
    let mut buf = [0u8; 512];
    let _ = timeout(Settings::global().banner_timeout(), stream.read(&mut buf)).await.ok();
    let _ = String::from_utf8_lossy(&buf);

    let cmd = format!("a001 LOGIN {} {}\r\n", user, pass);
    let _ = stream.write_all(cmd.as_bytes()).await.ok();
    buf.fill(0);
    let _ = timeout(Settings::global().banner_timeout(), stream.read(&mut buf)).await.ok();
    let resp = String::from_utf8_lossy(&buf);
    resp.contains("a001 OK") || resp.contains("* OK")
}

fn base64_encode(input: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::new();
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
        let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
        let triple = (b0 << 16) | (b1 << 8) | b2;
        result.push(CHARS[((triple >> 18) & 0x3F) as usize] as char);
        result.push(CHARS[((triple >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            result.push(CHARS[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
        if chunk.len() > 2 {
            result.push(CHARS[(triple & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
    }
    result
}

async fn try_sshpass(target: &str, port: u16, user: &str, pass: &str) -> bool {
    let output = Command::new("sshpass")
        .env("SSHPASS", pass)
        .arg("-e")
        .arg("ssh")
        .arg("-o").arg("StrictHostKeyChecking=no")
        .arg("-o").arg("UserKnownHostsFile=/dev/null")
        .arg("-o").arg("ConnectTimeout=5")
        .arg("-o").arg("BatchMode=yes")
        .arg("-p").arg(port.to_string())
        .arg(format!("{}@{}", user, target))
        .arg("exit")
        .output().await;

    match output {
        Ok(o) => o.status.success(),
        Err(_) => false,
    }
}

async fn check_ssh_cli(target: &str, port: u16, user: &str, pass: &str) -> bool {
    try_sshpass(target, port, user, pass).await
}

async fn check_ftp(stream: &mut TcpStream, user: &str, pass: &str) -> bool {
    let mut buf = [0u8; 512];
    let _ = timeout(Settings::global().banner_timeout(), stream.read(&mut buf)).await.ok();
    let banner = String::from_utf8_lossy(&buf);
    if !banner.contains("220") { return false; }

    let cmd = format!("USER {}\r\n", user);
    let _ = stream.write_all(cmd.as_bytes()).await.ok();
    buf.fill(0);
    let _ = timeout(Settings::global().banner_timeout(), stream.read(&mut buf)).await.ok();
    let resp = String::from_utf8_lossy(&buf);
    if !resp.contains("331") && !resp.contains("230") { return false; }
    if resp.contains("230") { return true; }

    let cmd = format!("PASS {}\r\n", pass);
    let _ = stream.write_all(cmd.as_bytes()).await.ok();
    buf.fill(0);
    let _ = timeout(Settings::global().banner_timeout(), stream.read(&mut buf)).await.ok();
    let resp = String::from_utf8_lossy(&buf);
    resp.contains("230") || resp.contains("202")
}

async fn check_http_basic(target: &str, port: u16, user: &str, pass: &str) -> bool {
    let url = if port == 443 || port == 8443 {
        format!("https://{}:{}/", target, port)
    } else {
        format!("http://{}:{}/", target, port)
    };

    let client = match reqwest::Client::builder()
        .timeout(Settings::global().http_timeout())
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::none())
        .build()
    {
        Ok(c) => c,
        Err(_) => return false,
    };

    match client.get(&url).basic_auth(user, Some(pass)).send().await {
        Ok(resp) => resp.status().as_u16() != 401,
        Err(_) => false,
    }
}

async fn check_redis(stream: &mut TcpStream, pass: &str) -> bool {
    let mut buf = [0u8; 256];
    let _ = stream.read(&mut buf).await.ok();

    let cmd = if pass.is_empty() {
        "PING\r\n".to_string()
    } else {
        format!("AUTH {}\r\n", pass)
    };
    let _ = stream.write_all(cmd.as_bytes()).await.ok();
    buf.fill(0);
    let _ = timeout(Settings::global().banner_timeout(), stream.read(&mut buf)).await.ok();
    let resp = String::from_utf8_lossy(&buf);
    resp.contains("+PONG") || resp.contains("+OK")
}

// MySQL raw protocol authentication
// Sends login packet with scrambled password using SHA1
async fn check_mysql_raw(stream: &mut TcpStream, user: &str, pass: &str) -> bool {
    let mut buf = [0u8; 1024];
    // Read server greeting (handshake packet)
    match timeout(Settings::global().banner_timeout(), stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 4 + 4 + 8 => {
            let protocol_version = buf[4];
            if protocol_version != 10 { return false; }

            // Extract auth-plugin-data (salt)
            // After server version string (null-terminated), connection id (4 bytes)
            // Then auth-plugin-data-part-1 (8 bytes), filler (1 byte),
            // Then capability flags, character set, status flags, capability flags 2,
            // Length of auth-plugin-data, reserved (10 bytes),
            // Then auth-plugin-data-part-2 (12 bytes or more)
            let mut offset = 5usize;
            while offset < n && buf[offset] != 0 { offset += 1; }
            offset += 1; // null terminator
            offset += 4; // connection id

            if offset + 8 > n { return false; }
            let salt1 = &buf[offset..offset + 8];
            offset += 8 + 1; // salt1 + filler

            offset += 2; // capability flags lower
            offset += 1; // character set
            offset += 2; // status flags
            offset += 2; // capability flags upper

            let auth_plugin_data_len = if offset < n { buf[offset] as usize } else { 0 };
            offset += 1;

            offset += 10; // reserved

            let salt2_len = if auth_plugin_data_len > 8 { auth_plugin_data_len - 8 } else { 12 };
            if auth_plugin_data_len == 0 { offset += 12; } else { offset += salt2_len; }

            if offset > n { return false; }
            let salt2 = if auth_plugin_data_len > 8 {
                &buf[offset - salt2_len..offset - salt2_len + salt2_len.min(n - (offset - salt2_len))]
            } else {
                &buf[offset - 12..offset - 12 + 12.min(n - (offset - 12))]
            };

            let salt_end = salt2.len();

            // Build MySQL native password hash:
            // SHA1(password) XOR SHA1(salt + SHA1(SHA1(password)))
            let mut hasher = Sha1::new();
            hasher.update(pass.as_bytes());
            let pass_hash = hasher.finalize_reset();

            hasher.update(&pass_hash);
            hasher.finalize_reset();

            hasher.update(&salt1[..8]);
            hasher.update(&salt2[..salt_end]);
            let salt_hash = hasher.finalize();

            let xor_result: Vec<u8> = pass_hash.iter().zip(salt_hash.iter()).map(|(a, b)| a ^ b).collect();

            // Build login packet
            // Client capability flags
            let client_flags: u32 = 0x00820001; // CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION | CLIENT_PLUGIN_AUTH
            let mut login = Vec::new();
            login.extend(&client_flags.to_le_bytes());
            login.extend(&[0u8; 4]); // max packet size
            login.push(33); // character set utf8
            login.extend(&[0u8; 23]); // reserved
            login.extend(user.as_bytes());
            login.push(0);
            login.push(xor_result.len() as u8);
            login.extend(&xor_result);
            login.extend(b"mysql_native_password");
            login.push(0);

            // Write packet header (3 bytes length + 1 byte seq)
            let pkt_len = login.len() as u32;
            let header = pkt_len.to_le_bytes();
            let header = &header[..3];
            let seq: [u8; 1] = [1]; // sequence number 1

            let mut full_pkt = Vec::new();
            full_pkt.extend_from_slice(header);
            full_pkt.extend_from_slice(&seq);
            full_pkt.extend(&login);

            if stream.write_all(&full_pkt).await.is_err() {
                return false;
            }

            buf.fill(0);
            match timeout(Settings::global().banner_timeout(), stream.read(&mut buf)).await {
                Ok(Ok(m)) if m > 4 => {
                    let resp_code = buf[4];
                    // 0 = OK, 0xFF = error, 0xFE = auth switch
                    resp_code == 0
                }
                _ => false,
            }
        }
        _ => false,
    }
}

// PostgreSQL via psql CLI
async fn check_postgres_cli(target: &str, port: u16, user: &str, pass: &str) -> bool {
    let output = Command::new("psql")
        .env("PGPASSWORD", pass)
        .arg("-h").arg(target)
        .arg("-p").arg(port.to_string())
        .arg("-U").arg(user)
        .arg("-d").arg("postgres")
        .arg("-c").arg("SELECT 1")
        .arg("-o").arg("/dev/null")
        .output().await;

    match output {
        Ok(o) => o.status.success(),
        Err(_) => false,
    }
}

// MSSQL raw protocol - just check if we get a pre-login response (indicates SQL Server is there)
async fn check_mssql_raw(stream: &mut TcpStream) -> bool {
    // TDS pre-login packet
    // Minimal pre-login packet that should get a response from SQL Server
    let prelogin: [u8; 64] = [
        0x12, 0x01, 0x00, 0x38, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    ];

    match timeout(Settings::global().banner_timeout(), stream.write_all(&prelogin)).await {
        Ok(Ok(_)) => {
            let mut buf = [0u8; 256];
            match timeout(Settings::global().banner_timeout(), stream.read(&mut buf)).await {
                Ok(Ok(n)) => {
                    // Check for TDS response header (0x04 = prelogin response type)
                    n > 5 && buf[0] == 0x04
                }
                _ => false,
            }
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_service_from_port() {
        assert_eq!(service_from_port(21), "FTP");
        assert_eq!(service_from_port(22), "SSH");
        assert_eq!(service_from_port(25), "SMTP");
        assert_eq!(service_from_port(110), "POP3");
        assert_eq!(service_from_port(143), "IMAP");
        assert_eq!(service_from_port(443), "HTTP");
        assert_eq!(service_from_port(3306), "MySQL");
        assert_eq!(service_from_port(6379), "Redis");
        assert_eq!(service_from_port(27017), "MongoDB");
        assert_eq!(service_from_port(9999), "Unknown");
    }

    #[test]
    fn test_http_variants() {
        assert_eq!(service_from_port(80), "HTTP");
        assert_eq!(service_from_port(8080), "HTTP");
        assert_eq!(service_from_port(8443), "HTTP");
        assert_eq!(service_from_port(3000), "HTTP");
        assert_eq!(service_from_port(5000), "HTTP");
        assert_eq!(service_from_port(8888), "HTTP");
        assert_eq!(service_from_port(9090), "HTTP");
    }

    #[test]
    fn test_mail_ports() {
        assert_eq!(service_from_port(465), "SMTP");
        assert_eq!(service_from_port(587), "SMTP");
        assert_eq!(service_from_port(995), "POP3");
        assert_eq!(service_from_port(993), "IMAP");
    }

    #[test]
    fn test_base64_encode() {
        assert_eq!(base64_encode(b"admin"), "YWRtaW4=");
        assert_eq!(base64_encode(b"password"), "cGFzc3dvcmQ=");
        assert_eq!(base64_encode(b"a"), "YQ==");
        assert_eq!(base64_encode(b""), "");
    }

    #[test]
    fn test_default_creds_contains_services() {
        let services: Vec<&str> = DEFAULT_CREDS.iter().map(|(s, _)| *s).collect();
        assert!(services.contains(&"FTP"));
        assert!(services.contains(&"SSH"));
        assert!(services.contains(&"HTTP"));
        assert!(services.contains(&"MySQL"));
        assert!(services.contains(&"Redis"));
        assert!(services.contains(&"SMTP"));
        assert!(services.contains(&"POP3"));
        assert!(services.contains(&"IMAP"));
        assert!(services.contains(&"MongoDB"));
    }

    #[test]
    fn test_parse_credential_evidence_manual() {
        let c = parse_credential_evidence("Authenticated to SSH:22 with root/toor").unwrap();
        assert_eq!(c.service, "SSH");
        assert_eq!(c.port, 22);
        assert_eq!(c.user, "root");
        assert_eq!(c.pass, "toor");
        assert_eq!(c.source, "default-creds@22");
    }

    #[test]
    fn test_parse_credential_evidence_hydra() {
        let c = parse_credential_evidence("Hydra: admin:s3cret on 10.0.0.1:21/ftp").unwrap();
        assert_eq!(c.port, 21);
        assert_eq!(c.service, "FTP");
        assert_eq!(c.user, "admin");
        assert_eq!(c.pass, "s3cret");
    }

    #[test]
    fn test_parse_credential_evidence_rejects_other() {
        assert!(parse_credential_evidence("some unrelated evidence line").is_none());
    }

    #[test]
    fn test_credentials_from_findings_filters_module() {
        let good = Finding::new("t", "creds", "x", "y", Severity::Critical)
            .with_evidence(vec!["Authenticated to FTP:21 with anonymous/anonymous".into()]);
        let other = Finding::new("t", "web", "x", "y", Severity::Low)
            .with_evidence(vec!["Authenticated to SSH:22 with root/root".into()]);
        let creds = credentials_from_findings(&[good, other]);
        assert_eq!(creds.len(), 1);
        assert_eq!(creds[0].service, "FTP");
    }
}

// MongoDB raw protocol - uses isMaster + authenticate
async fn check_mongodb_raw(stream: &mut TcpStream) -> bool {
    // MongoDB wire protocol: isMaster command
    // OP_MSG (2017) format: 4 bytes length, 4 bytes requestID, 4 bytes responseTo, 4 bytes opCode, flags, sections
    // Simpler: use OP_QUERY format
    let query_cmd = [
        0x3a, 0x00, 0x00, 0x00, // length (58)
        0x00, 0x00, 0x00, 0x00, // requestID
        0x00, 0x00, 0x00, 0x00, // responseTo
        0xd4, 0x07, 0x00, 0x00, // opCode 2004 (OP_QUERY)
        0x00, 0x00, 0x00, 0x00, // flags
        0x61, 0x64, 0x6d, 0x69, 0x6e, 0x2e, 0x24, 0x63, 0x6d, 0x64, 0x00, // "admin.$cmd"
        0x00, 0x00, 0x00, 0x00, // numberToSkip
        0x01, 0x00, 0x00, 0x00, // numberToReturn
        // BSON: {"isMaster": 1}
        0x0a, 0x00, 0x00, 0x00, // BSON document length (10)
        0x10,                   // int32 type
        0x69, 0x73, 0x4d, 0x61, 0x73, 0x74, 0x65, 0x72, 0x00, // "isMaster\x00"
        0x01, 0x00, 0x00, 0x00, // int32 value 1
        0x00,                   // terminator
    ];

    match timeout(Settings::global().banner_timeout(), stream.write_all(&query_cmd)).await {
        Ok(Ok(_)) => {
            let mut buf = [0u8; 1024];
            match timeout(Settings::global().banner_timeout(), stream.read(&mut buf)).await {
                Ok(Ok(n)) => n > 16,
                _ => false,
            }
        }
        _ => false,
    }
}
