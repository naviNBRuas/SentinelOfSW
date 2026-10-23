use crate::core::config::Settings;
use crate::core::docker::global_docker;
use crate::core::findings::Finding;
use crate::core::knowledge::KnowledgeBase;
use crate::core::tools::run_nmap;
use crate::core::workflow::WorkflowMode;
use crate::modules::Module;
use async_trait::async_trait;
use std::sync::Arc;
use std::time::Instant;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::sync::mpsc::Sender;
use tokio::sync::Semaphore;
use tokio::time::{timeout, Duration};

#[derive(Debug, Clone)]
pub struct OsFingerprint {
    pub os_family: String,
    pub confidence: f32,
    pub ttl: u32,
}

impl OsFingerprint {
    /// Detect OS from initial TTL value in TCP connection.
    /// Common TTL defaults: Windows = 128, Linux = 64, BSD/macOS = 64, Solaris = 255,
    /// Cisco IOS = 255, Android = 64.
    pub fn from_ttl(ttl: u32) -> Self {
        let (os_family, confidence) = match ttl {
            0..=32 => ("Unknown (low TTL — likely behind NAT/proxy)".to_string(), 0.3),
            33..=63 => ("Unix/Linux (TTL 64)".to_string(), 0.6),
            64 => ("Linux/Unix".to_string(), 0.8),
            65..=127 => ("Windows (TTL 128)".to_string(), 0.6),
            128 => ("Windows".to_string(), 0.85),
            129..=254 => ("Solaris/Cisco (TTL 255)".to_string(), 0.6),
            255 => ("Solaris/Cisco IOS".to_string(), 0.8),
            _ => ("Unknown".to_string(), 0.2),
        };
        Self { os_family, confidence, ttl }
    }
}

pub struct PortScanner;

impl PortScanner {

    fn identify_service(port: u16) -> &'static str {
        match port {
            21 => "FTP", 22 => "SSH", 23 => "Telnet", 25 => "SMTP", 53 => "DNS",
            80 => "HTTP", 110 => "POP3", 111 => "RPC", 135 => "MSRPC", 139 => "NetBIOS-SSN",
            143 => "IMAP", 161 => "SNMP", 389 => "LDAP", 443 => "HTTPS", 445 => "SMB",
            465 => "SMTPS", 500 => "IKE", 513 => "RLogin", 554 => "RTSP", 587 => "SMTP-Submit",
            593 => "MSRPC-HTTPS", 636 => "LDAPS", 873 => "Rsync", 990 => "FTPS",
            993 => "IMAPS", 995 => "POP3S", 1433 => "MSSQL", 1521 => "Oracle-DB",
            1723 => "PPTP", 2049 => "NFS", 2082 => "cPanel", 2083 => "cPanel-SSL",
            2181 => "ZooKeeper", 2222 => "SSH-Alt", 2375 => "Docker-REST",
            2376 => "Docker-TLS", 2443 => "HTTPS-Alt", 3000 => "HTTP-Dev", 3128 => "Squid-Proxy",
            3268 => "LDAP-GC", 3269 => "LDAP-GC-SSL", 3306 => "MySQL", 3389 => "RDP",
            3478 => "STUN", 3632 => "distcc", 3690 => "SVN", 4000 => "HTTP-Alt",
            4040 => "HTTP-Alt", 4444 => "Metasploit", 4500 => "IPsec-NAT-T",
            4848 => "GlassFish", 5000 => "HTTP-Alt", 5432 => "PostgreSQL",
            5555 => "Android-ADB", 5601 => "Kibana", 5666 => "NRPE", 5672 => "AMQP",
            5800 => "VNC-HTTP", 5900 => "VNC", 5901 => "VNC-1", 5984 => "CouchDB",
            5985 => "WinRM", 5986 => "WinRM-SSL", 6000 => "X11", 6379 => "Redis",
            6443 => "Kubernetes", 6660..=6669 => "IRC", 6697 => "IRC-SSL",
            7000..=7002 => "HTTP-Alt", 7070..=7077 => "HTTP-Alt", 7777 => "HTTP-Alt",
            8000..=8100 => "HTTP-Alt", 8181 => "HTTP-Alt", 8222 => "HTTP-Alt",
            8243 => "HTTPS-Alt", 8280 => "HTTP-Alt", 8300 => "HTTP-Alt", 8400 => "HTTP-Alt",
            8443 => "HTTPS-Alt", 8500 => "HTTP-Alt", 8600 => "HTTP-Alt", 8649 => "Ganglia",
            8834 => "Nessus", 8880 => "HTTP-Alt", 8888 => "HTTP-Alt",
            9000..=9010 => "HTTP-Alt", 9042 => "Cassandra", 9050 => "HTTP-Alt",
            9060 => "HTTP-Alt", 9080 => "HTTP-Alt", 9090 => "HTTP-Alt", 9091 => "HTTP-Alt",
            9100 => "JetDirect", 9200 => "Elasticsearch", 9300 => "ES-Transport",
            9418 => "Git", 9443 => "HTTPS-Alt", 9999 => "HTTP-Alt", 10000 => "Webmin",
            10050 => "Zabbix-Agent", 10051 => "Zabbix-Server", 10443 => "HTTPS-Alt",
            11000 => "HTTP-Alt", 11211 => "Memcached", 12345 => "NetBus",
            13337 => "HTTP-Alt", 16000..=16100 => "HTTP-Alt",
            17000..=17001 => "HTTP-Alt", 18080..=18200 => "HTTP-Alt",
            27017..=27019 => "MongoDB", 31337 => "BackOrifice",
            32764 => "Linksys", 32771..=32779 => "RPC",
            42000..=42001 => "HTTP-Alt", 43000..=43010 => "HTTP-Alt",
            49152..=49156 => "Windows-RPC",
            _ => "Unknown",
        }
    }

    /// Extract service version from a banner string.
    /// Parses common version patterns like "OpenSSH_8.9p1", "Apache/2.4.41", etc.
    fn extract_version(service: &str, banner: &str) -> Option<String> {
        let version_patterns = [
            (r"OpenSSH[_ ]([\d.]+p?\d*)", "OpenSSH"),
            (r"Apache[ /]([\d.]+)", "Apache"),
            (r"nginx[ /]([\d.]+)", "nginx"),
            (r"Microsoft-IIS[ /]([\d.]+)", "IIS"),
            (r"ProFTPD[ /]([\d.]+)", "ProFTPD"),
            (r"vsFTPd[ /]([\d.]+)", "vsFTPd"),
            (r"SSH[- ]?([\d.]+)", "SSH"),
            (r"mysql_native_password", "MySQL"),
            (r"PostgreSQL ([\d.]+)", "PostgreSQL"),
            (r"Redis[\s]?server[\s]?v=([\d.]+)", "Redis"),
        ];
        for (pattern, _name) in &version_patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                if let Some(cap) = re.captures(banner) {
                    if let Some(ver) = cap.get(1) {
                        return Some(format!("{} v{}", service, ver.as_str()));
                    }
                }
            }
        }
        None
    }

    async fn grab_banner(target: &str, port: u16) -> Option<String> {
        let cfg = Settings::global();
        let banner_timeout = cfg.banner_timeout();
        let addr = format!("{}:{}", target, port);
        match timeout(banner_timeout, TcpStream::connect(&addr)).await {
            Ok(Ok(mut stream)) => {
                let mut buf = vec![0u8; 1024];
                match timeout(banner_timeout, stream.read(&mut buf)).await {
                    Ok(Ok(n)) if n > 0 => {
                        buf.truncate(n);
                        let banner: String = buf.iter()
                            .take_while(|&&b| b.is_ascii_graphic() || b == b' ' || b == b'\n' || b == b'\r')
                            .map(|&b| b as char)
                            .collect();
                        let banner = banner.trim().to_string();
                        if !banner.is_empty() && banner.len() > 5 {
                            Some(banner)
                        } else {
                            None
                        }
                    }
                    _ => None,
                }
            }
            _ => None,
        }
    }

    async fn scan_with_nmap(target: &str, ports: &[u16], is_ctf: bool, tx: &Sender<String>) -> Vec<Finding> {
        let docker = global_docker();
        let nmap_args = if is_ctf {
            vec!["-sV", "--version-intensity", "9", "-T4", "--open"]
        } else {
            vec!["-sV", "-T4", "--open"]
        };

        let _ = tx.send(format!("[Port Scanner] Running nmap scan ({} ports)...", ports.len())).await;
        let result = run_nmap(target, ports, &nmap_args, docker.map(|a| &**a), 300).await;

        if result.exit_code != 0 && !result.stdout.contains("Nmap") {
            let _ = tx.send(format!("[Port Scanner] nmap failed ({}), falling back to internal scanner", result.stderr.trim())).await;
            return Vec::new();
        }

        let mut findings = Vec::new();
        let mut open_ports: Vec<u16> = Vec::new();
        for line in result.stdout.lines() {
            if !line.contains("/open/") {
                continue;
            }
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 3 {
                continue;
            }
            let port_part = parts[0];
            let port: u16 = match port_part.split('/').next().and_then(|s| s.parse().ok()) {
                Some(p) => p,
                None => continue,
            };

            let service_name = if parts.len() >= 4 && !parts[3].is_empty() && parts[3] != "?" {
                let svc = parts[3].trim_matches(|c: char| c == '/' || c == '?');
                let version_info: Vec<&str> = parts.iter().skip(4).take_while(|p| !p.starts_with("http") && !p.starts_with("ssl") && !p.starts_with("filtered")).copied().collect();
                if version_info.is_empty() {
                    svc.to_string()
                } else {
                    format!("{} {}", svc, version_info.join(" "))
                }
            } else {
                PortScanner::identify_service(port).to_string()
            };

            open_ports.push(port);
            let _ = tx.send(format!("[Port Scanner] nmap found: {}/{} ({})", port, service_name, line.split_whitespace().nth(1).unwrap_or("?"))).await;

            let severity = match port {
                21 | 23 => crate::core::findings::Severity::Medium,
                22 | 80 | 443 => crate::core::findings::Severity::Low,
                445 | 3389 => crate::core::findings::Severity::High,
                _ => crate::core::findings::Severity::Info,
            };

            let finding = Finding::new(
                target,
                "port_scan",
                &format!("Open Port: {}/{}", port, service_name),
                &format!("Port {} ({}) is open — discovered via nmap.", port, service_name),
                severity,
            )
            .with_confidence(0.98)
            .with_education(KnowledgeBase::for_open_port(port, &service_name))
            .with_evidence(vec![format!("nmap: port {} open - {}", port, service_name)]);

            findings.push(finding);

            if open_ports.len() >= 100 {
                break;
            }
        }

        let _ = tx.send(format!("[Port Scanner] nmap scan complete. Found {} open ports.", open_ports.len())).await;
        findings
    }

    async fn scan_async(target: &str, ports: &[u16], is_ctf: bool, concurrency: usize, connect_timeout: Duration, tx: &Sender<String>) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut os_ttls: Vec<u32> = Vec::new();
        let sem = Arc::new(Semaphore::new(concurrency));
        let start = Instant::now();
        let stealth = crate::core::config::RuntimeOverrides::global().stealth_mode;

        let mut handles = Vec::new();
        for &port in ports {
            let sem = Arc::clone(&sem);
            let target = target.to_string();

            handles.push(tokio::spawn(async move {
                let _permit = sem.acquire().await.map_err(|_| ()).ok()?;

                // Stealth mode: random delay between connections
                if stealth {
                    let jitter = std::time::Duration::from_millis(rand::random::<u64>() % 500);
                    tokio::time::sleep(jitter).await;
                }

                let addr = format!("{}:{}", target, port);
                let t = Instant::now();
                let result = timeout(connect_timeout, TcpStream::connect(&addr)).await;
                let elapsed = t.elapsed();
                match result {
                    Ok(Ok(stream)) => {
                        // Capture TTL from socket for OS fingerprinting
                        let ttl = stream.ttl().unwrap_or(64);
                        Some((port, elapsed, ttl))
                    }
                    _ => None,
                }
            }));
        }

        for handle in handles {
            if let Some((port, elapsed, ttl)) = handle.await.unwrap_or(None) {
                os_ttls.push(ttl);
                let service = PortScanner::identify_service(port);
                let _ = tx.send(format!("[Port Scanner] Open: {}/{} ({}ms, TTL={})", port, service, elapsed.as_millis(), ttl)).await;

                let banner = if is_ctf && service == "Unknown" {
                    PortScanner::grab_banner(target, port).await
                } else {
                    None
                };

                let mut finding = Finding::new(
                    target,
                    "port_scan",
                    &format!("Open Port: {}/{}", port, service),
                    &format!("Port {} ({}) is open.", port, service),
                    match port {
                        21 | 23 => crate::core::findings::Severity::Medium,
                        22 | 80 | 443 => crate::core::findings::Severity::Low,
                        445 | 3389 => crate::core::findings::Severity::High,
                        _ => crate::core::findings::Severity::Info,
                    },
                )
                .with_confidence(0.95)
                .with_education(KnowledgeBase::for_open_port(port, service))
                .with_evidence(vec![format!("TCP connection to port {} successful ({:?}, TTL={})", port, elapsed, ttl)]);

                if let Some(b) = banner {
                    finding.evidence.push(format!("Banner: {}", b));
                    if let Some(version) = PortScanner::extract_version(service, &b) {
                        finding.evidence.push(format!("Version: {}", version));
                        finding.title = format!("Open Port: {}/{} ({})", port, service, version);
                    }
                }

                findings.push(finding);
            }
        }

        // OS fingerprinting from collected TTL values
        if !os_ttls.is_empty() {
            let most_common_ttl = os_ttls.iter().fold(std::collections::HashMap::new(), |mut acc, &ttl| {
                *acc.entry(ttl).or_insert(0) += 1;
                acc
            }).into_iter().max_by_key(|&(_, count)| count).map(|(ttl, _)| ttl);

            if let Some(avg_ttl) = most_common_ttl {
                let fp = OsFingerprint::from_ttl(avg_ttl);
                let _ = tx.send(format!("[Port Scanner] OS detection: {} (TTL={}, confidence={:.0}%)", fp.os_family, fp.ttl, fp.confidence * 100.0)).await;
                findings.push(
                    Finding::new(
                        target,
                        "port_scan",
                        &format!("OS Detection: {}", fp.os_family),
                        &format!("Target OS fingerprint based on TCP TTL analysis. Detected as {} with {}% confidence.", fp.os_family, (fp.confidence * 100.0) as u32),
                        crate::core::findings::Severity::Info,
                    ).with_confidence(fp.confidence)
                    .with_evidence(vec![format!("TTL fingerprint: {} (observed on {} open ports)", fp.ttl, os_ttls.len())])
                );
            }
        }

        let total_elapsed = start.elapsed();
        let _ = tx.send(format!("[Port Scanner] Async scan complete ({} ports in {:?}). Found {} open ports.", ports.len(), total_elapsed, findings.len())).await;
        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identify_known_ports() {
        assert_eq!(PortScanner::identify_service(22), "SSH");
        assert_eq!(PortScanner::identify_service(80), "HTTP");
        assert_eq!(PortScanner::identify_service(443), "HTTPS");
        assert_eq!(PortScanner::identify_service(445), "SMB");
        assert_eq!(PortScanner::identify_service(3306), "MySQL");
        assert_eq!(PortScanner::identify_service(3389), "RDP");
        assert_eq!(PortScanner::identify_service(6379), "Redis");
        assert_eq!(PortScanner::identify_service(27017), "MongoDB");
    }

    #[test]
    fn test_identify_unknown_port() {
        assert_eq!(PortScanner::identify_service(65535), "Unknown");
        assert_eq!(PortScanner::identify_service(1), "Unknown");
    }

    #[test]
    fn test_identify_range_ports() {
        assert_eq!(PortScanner::identify_service(6667), "IRC");
        assert_eq!(PortScanner::identify_service(7070), "HTTP-Alt");
        assert_eq!(PortScanner::identify_service(8001), "HTTP-Alt");
    }
}

#[async_trait]
impl Module for PortScanner {
    fn name(&self) -> &str {
        "Port Scanner"
    }

    async fn execute_with_ports(&self, target: &str, _open_ports: &[u16], mode: &WorkflowMode, tx: Sender<String>) -> Result<Vec<Finding>, anyhow::Error> {
        let cfg = Settings::global();
        let is_ctf = matches!(mode, WorkflowMode::Ctf);
        let is_quick = matches!(mode, WorkflowMode::Quick);
        let ports: Vec<u16> = if is_ctf {
            let _ = tx.send("[Port Scanner] CTF mode: scanning all common port ranges (~6500 ports)".into()).await;
            cfg.resolve_ports_ctf()
        } else if is_quick {
            let _ = tx.send("[Port Scanner] Quick mode: scanning 31 common ports".into()).await;
            cfg.resolve_ports_quick()
        } else {
            cfg.resolve_ports_default()
        };

        // Try nmap via Docker first if available (CTF mode)
        if global_docker().is_some() && !is_quick {
            let nmap_findings = Self::scan_with_nmap(target, &ports, is_ctf, &tx).await;
            if !nmap_findings.is_empty() {
                return Ok(nmap_findings);
            }
        }

        let _connect_timeout = if is_ctf { cfg.ctf_connect_timeout() } else { cfg.connect_timeout() };
        let _concurrency = if is_ctf { cfg.port_scan_ctf_concurrency() } else { cfg.port_scan_concurrency() };

        // Filter excluded ports
        let excluded = crate::core::config::RuntimeOverrides::global().exclude_ports.clone();
        let filtered_ports: Vec<u16> = ports.into_iter().filter(|p| !excluded.contains(p)).collect();
        if !excluded.is_empty() {
            let _ = tx.send(format!("[Port Scanner] Excluded {} ports, scanning {} remaining", excluded.len(), filtered_ports.len())).await;
        }

        if filtered_ports.is_empty() {
            let _ = tx.send("[Port Scanner] All ports excluded, nothing to scan".into()).await;
            return Ok(Vec::new());
        }

        let connect_timeout = if is_ctf { cfg.ctf_connect_timeout() } else { cfg.connect_timeout() };
        let concurrency = if is_ctf { cfg.port_scan_ctf_concurrency() } else { cfg.port_scan_concurrency() };

        let _ = tx.send(format!("[Port Scanner] Starting async scan of {} ({} ports, {} concurrent)", target, filtered_ports.len(), concurrency)).await;
        let findings = Self::scan_async(target, &filtered_ports, is_ctf, concurrency, connect_timeout, &tx).await;
        Ok(findings)
    }
}
