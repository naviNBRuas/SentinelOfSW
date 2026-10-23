use crate::core::findings::{Finding, Severity};
use crate::core::knowledge::KnowledgeBase;
use crate::core::workflow::WorkflowMode;
use crate::core::config::Settings;
use crate::modules::Module;
use async_trait::async_trait;
use hickory_resolver::proto::rr::record_type::RecordType;
use hickory_resolver::Resolver;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{lookup_host, TcpStream};
use tokio::sync::mpsc::Sender;
use tokio::sync::Semaphore;
use tokio::time::timeout;

const SUBDOMAIN_WORDLIST: &[&str] = &[
    "www", "mail", "admin", "vpn", "dev", "staging", "api", "blog", "cdn", "static",
    "test", "beta", "app", "web", "webmail", "portal", "intranet", "remote", "support",
    "help", "helpdesk", "docs", "wiki", "forum", "community", "status", "git", "jenkins",
    "jira", "confluence", "grafana", "prometheus", "kibana", "elastic", "splunk",
    "nagios", "zabbix", "cacti", "puppet", "chef", "ansible", "docker", "k8s",
    "kubernetes", "swagger", "api-docs", "graphql", "playground", "console", "monitor",
    "dashboard", "analytics", "metrics", "backup", "db", "database", "redis", "mysql",
    "mongo", "postgres", "sql", "files", "upload", "download", "assets", "resources",
    "img", "images", "css", "js", "fonts", "media", "video", "stream", "proxy",
    "gateway", "auth", "login", "sso", "oauth", "saml", "ldap", "radius",
    "exchange", "owa", "autodiscover", "lync", "skype", "teams", "zoom",
    "phone", "mta", "mx", "ns1", "ns2", "ns3", "smtp", "pop", "imap",
    "caldav", "carddav", "webdav", "dav", "svn", "gitlab", "bitbucket",
    "registry", "nexus", "artifactory", "maven", "npm", "pypi", "rubygems",
    "cocoapods", "jenkins", "teamcity", "bamboo", "circleci", "travis",
    "ci", "cd", "build", "deploy", "release", "version", "latest",
    "stage", "prod", "production", "development", "testing", "qa",
    "internal", "external", "public", "private", "corp", "office",
    "hr", "payroll", "finance", "accounting", "invoices", "billing",
    "reports", "compliance", "audit", "security", "incident",
    "survey", "forms", "register", "signup", "signin", "logout",
    "forgot", "reset", "password", "profile", "settings", "preferences",
    "config", "configuration", "setup", "install", "guide", "manual",
    "news", "press", "careers", "jobs", "about", "contact", "feedback",
    "partner", "partners", "vendor", "vendors", "supplier", "reseller",
    "api/v1", "api/v2", "api/v3", "rest", "soap", "xmlrpc", "jsonrpc",
    "rpc", "grpc", "ws", "websocket", "socket", "ssh", "sftp", "ftp",
    "s3", "bucket", "storage", "cloud", "s3.amazonaws.com",
];

pub struct DnsRecon;

/// Attempt DNS zone transfer by querying each discovered NS with AXFR
async fn attempt_axfr(domain: &str) -> Result<Option<Vec<String>>, anyhow::Error> {
    // First resolve NS records to find nameservers
    use hickory_resolver::Resolver;
    let resolver_builder = Resolver::builder_tokio();
    let resolver = match resolver_builder {
        Ok(builder) => builder.build(),
        Err(_) => return Ok(None),
    };

    let ns_records = match resolver.ns_lookup(domain).await {
        Ok(response) => {
            let nss: Vec<String> = response.iter()
                .map(|ns| ns.to_string().trim_end_matches('.').to_string())
                .collect();
            nss
        }
        Err(_) => return Ok(None),
    };

    if ns_records.is_empty() {
        return Ok(None);
    }

    // Try each nameserver
    for ns in &ns_records {
        let addr = format!("{}:53", ns);
        if let Ok(mut stream) = TcpStream::connect(&addr).await {
            // Build AXFR query packet
            // Header: ID (2), flags (2), QDCOUNT (2), ANCOUNT (2), NSCOUNT (2), ARCOUNT (2)
            let mut pkt = Vec::new();
            pkt.extend_from_slice(&[0x00, 0x01]); // ID
            pkt.extend_from_slice(&[0x01, 0x00]); // flags: recursion desired
            pkt.extend_from_slice(&[0x00, 0x01]); // QDCOUNT: 1 question
            pkt.extend_from_slice(&[0x00, 0x00]); // ANCOUNT: 0
            pkt.extend_from_slice(&[0x00, 0x00]); // NSCOUNT: 0
            pkt.extend_from_slice(&[0x00, 0x00]); // ARCOUNT: 0

            // Question: domain name encoded
            for part in domain.split('.') {
                pkt.push(part.len() as u8);
                pkt.extend_from_slice(part.as_bytes());
            }
            pkt.push(0x00); // end of name
            pkt.extend_from_slice(&[0x00, 0xFC]); // QTYPE: AXFR (252)
            pkt.extend_from_slice(&[0x00, 0x01]); // QCLASS: IN

            // TCP DNS uses 2-byte length prefix
            let len = (pkt.len() as u16).to_be_bytes();
            let mut tcp_pkt = Vec::new();
            tcp_pkt.extend_from_slice(&len);
            tcp_pkt.extend(&pkt);

            if stream.write_all(&tcp_pkt).await.is_err() {
                continue;
            }

            // Read response
            let mut len_buf = [0u8; 2];
            match timeout(Settings::global().dns_timeout(), stream.read_exact(&mut len_buf)).await {
                Ok(Ok(_)) => {
                    let resp_len = u16::from_be_bytes(len_buf) as usize;
                    let mut resp = vec![0u8; resp_len];
                    if timeout(Settings::global().dns_timeout(), stream.read_exact(&mut resp)).await.is_ok() {
                        // Parse response for zone data
                        if resp.len() < 12 { continue; }
                        let ancount = u16::from_be_bytes([resp[6], resp[7]]);
                        if ancount > 0 {
                            let mut records = Vec::new();
                            records.push(format!("AXFR successful via {}", ns));
                            // Extract domain names from answer section (simplified)
                            let mut pos = 12; // skip header
                            // Skip question section
                            while pos < resp.len() {
                                if resp[pos] == 0 { pos += 1; break; }
                                if resp[pos] & 0xC0 == 0xC0 { pos += 2; break; }
                                pos += 1 + resp[pos] as usize;
                            }
                            pos += 4; // skip QTYPE + QCLASS

                            for _ in 0..ancount {
                                if pos + 12 > resp.len() { break; }
                                // Skip name (could be pointer)
                                if resp[pos] & 0xC0 == 0xC0 {
                                    pos += 2;
                                } else {
                                    while pos < resp.len() && resp[pos] != 0 { pos += 1 + resp[pos] as usize; }
                                    pos += 1;
                                }
                                let rtype = u16::from_be_bytes([resp[pos], resp[pos + 1]]);
                                pos += 2;
                                // rclass
                                pos += 2;
                                // ttl
                                pos += 4;
                                let rdlength = u16::from_be_bytes([resp[pos], resp[pos + 1]]) as usize;
                                pos += 2;
                                let rdata_str = match rtype {
                                    1 | 28 => { // A or AAAA
                                        if rdlength == 4 {
                                            format!("A {}", std::net::Ipv4Addr::new(resp[pos], resp[pos+1], resp[pos+2], resp[pos+3]))
                                        } else if rdlength == 16 {
                                            // simplified IPv6
                                            "AAAA (IPv6)".to_string()
                                        } else { format!("TYPE{}", rtype) }
                                    }
                                    2 => { // NS
                                        format!("NS ({} bytes)", rdlength)
                                    }
                                    5 => { // CNAME
                                        format!("CNAME ({} bytes)", rdlength)
                                    }
                                    15 => { // MX
                                        format!("MX ({} bytes)", rdlength)
                                    }
                                    _ => format!("TYPE{} ({} bytes)", rtype, rdlength),
                                };
                                records.push(rdata_str);
                                pos += rdlength;
                            }
                            return Ok(Some(records));
                        }
                    }
                }
                _ => continue,
            }
        }
    }
    Ok(None)
}

async fn resolve_subdomain(fqdn: &str) -> Result<Vec<IpAddr>, anyhow::Error> {
    let addr_str = format!("{}:0", fqdn);
    let result = timeout(Settings::global().dns_timeout(), lookup_host(&addr_str)).await;
    match result {
        Ok(Ok(addrs)) => {
            let ips: Vec<IpAddr> = addrs.map(|sa| sa.ip()).collect();
            if ips.is_empty() {
                Err(anyhow::anyhow!("no addresses"))
            } else {
                Ok(ips)
            }
        }
        Ok(Err(e)) => Err(anyhow::anyhow!("lookup failed: {}", e)),
        Err(_) => Err(anyhow::anyhow!("timeout")),
    }
}

#[async_trait]
impl Module for DnsRecon {
    fn name(&self) -> &str {
        "DNS Recon"
    }

    async fn execute_with_ports(&self, target: &str, _open_ports: &[u16], _mode: &WorkflowMode, tx: Sender<String>) -> Result<Vec<Finding>, anyhow::Error> {
        let _ = tx.send(format!("[DNS Recon] Starting enumeration for {}", target)).await;

        let target_base = if target.starts_with("http") {
            target.split("://").nth(1).and_then(|s| s.split('/').next()).unwrap_or(target)
        } else {
            target
        };

        let target_base = target_base.trim_end_matches('.');

        let mut findings = Vec::new();

        if IpAddr::from_str(target_base).is_ok() {
            let _ = tx.send("[DNS Recon] Target is an IP address, skipping subdomain enumeration".to_string()).await;
            findings.push(
                Finding::new(
                    target,
                    "recon",
                    "DNS Reconnaissance Skipped",
                    &format!("Target {} is an IP address. Subdomain enumeration only applies to domain names.", target),
                    Severity::Info,
                )
                .with_confidence(1.0),
            );
            return Ok(findings);
        }

        // DNS Zone Transfer (AXFR) attempt
        let _ = tx.send(format!("[DNS Recon] Attempting DNS zone transfer for {}...", target_base)).await;
        match attempt_axfr(target_base).await {
            Ok(Some(records)) => {
                if records.is_empty() {
                    let _ = tx.send("[DNS Recon] Zone transfer returned 0 records (likely denied)".into()).await;
                } else {
                    let _ = tx.send(format!("[DNS Recon] Zone transfer successful! {} records received.", records.len())).await;
                    findings.push(
                        Finding::new(target, "recon", "DNS Zone Transfer (AXFR) Successful",
                            &format!("DNS zone transfer succeeded for {}! {} records received. This is a critical misconfiguration revealing all DNS records.", target_base, records.len()),
                            Severity::Critical,
                        ).with_confidence(0.95)
                        .with_evidence(records.iter().take(20).map(|r| format!("AXFR: {}", r)).collect())
                        .with_education(KnowledgeBase::for_subdomain(target_base)));
                }
            }
            Ok(None) => {
                let _ = tx.send("[DNS Recon] Zone transfer failed (no response)".into()).await;
            }
            Err(e) => {
                let _ = tx.send(format!("[DNS Recon] Zone transfer error: {}", e)).await;
            }
        }

        let wordlist: Vec<String> = Settings::global().subdomain_wordlist(SUBDOMAIN_WORDLIST).unwrap_or_else(|_| SUBDOMAIN_WORDLIST.iter().map(|s| s.to_string()).collect());

        let _ = tx.send(format!("[DNS Recon] Resolving A/AAAA records for {} subdomains...", wordlist.len())).await;

        let semaphore = Arc::new(Semaphore::new(Settings::global().dns_semaphore()));
        let mut handles = Vec::new();
        let mut discovered_subs: Vec<String> = Vec::new();

        for sub in &wordlist {
            let fqdn = format!("{}.{}", sub, target_base);
            let tx = tx.clone();
            let sem = Arc::clone(&semaphore);

            handles.push(tokio::spawn(async move {
                let _permit = sem.acquire().await;
                if _permit.is_err() {
                    return None;
                }

                match resolve_subdomain(&fqdn).await {
                    Ok(ips) => {
                        let ips_str: Vec<String> = ips.iter().map(|ip| ip.to_string()).collect();
                        let msg = format!("[DNS Recon] Found: {} → {}", fqdn, ips_str.join(", "));
                        let _ = tx.send(msg).await;
                        Some((fqdn, ips))
                    }
                    Err(_) => None,
                }
            }));
        }

        let mut resolved_count = 0;
        for handle in handles {
            if let Some((fqdn, ips)) = handle.await.unwrap_or(None) {
                resolved_count += 1;
                discovered_subs.push(fqdn.clone());
                let ips_str: Vec<String> = ips.iter().map(|ip| ip.to_string()).collect();
                findings.push(
                    Finding::new(
                        target,
                        "recon",
                        &format!("Subdomain Discovered: {}", fqdn),
                        &format!("Discovered subdomain {} resolving to {} during DNS enumeration.", fqdn, ips_str.join(", ")),
                        Severity::Info,
                    )
                    .with_confidence(0.95)
                    .with_education(KnowledgeBase::for_subdomain(&fqdn))
                    .with_evidence(vec![
                        format!("DNS A/AAAA record query for {} returned: {}", fqdn, ips_str.join(", ")),
                    ]),
                );
            }
        }

        // Enhanced DNS record enumeration using hickory-resolver
        let resolver_builder = Resolver::builder_tokio();
        if let Ok(builder) = resolver_builder {
            let resolver = builder.build();

            // SRV record lookup for common services
            let srv_services = ["_sip._tcp", "_sip._udp", "_sips._tcp",
                "_xmpp-client._tcp", "_xmpp-server._tcp",
                "_ldap._tcp", "_kerberos._tcp", "_kerberos._udp",
                "_imap._tcp", "_imaps._tcp", "_pop3._tcp", "_pop3s._tcp",
                "_smtp._tcp", "_submission._tcp",
                "_caldav._tcp", "_caldavs._tcp", "_carddav._tcp", "_carddavs._tcp",
                "_jabber._tcp", "_jabber._udp",
            ];
            for srv in &srv_services {
                let srv_name = format!("{}.{}", srv, target_base);
                if let Ok(response) = resolver.srv_lookup(&srv_name).await {
                    for record in response.iter() {
                        let target_srv = record.target().to_string().trim_end_matches('.').to_string();
                        let port_srv = record.port();
                        let _ = tx.send(format!("[DNS Recon] SRV: {} → {}:{}", srv_name, target_srv, port_srv)).await;
                        findings.push(
                            Finding::new(
                                target,
                                "recon",
                                &format!("SRV Record: {} → {}:{}", srv, target_srv, port_srv),
                                &format!("DNS SRV record for {} resolves to {} on port {}.", srv_name, target_srv, port_srv),
                                Severity::Info,
                            ).with_confidence(0.9)
                            .with_evidence(vec![format!("SRV {} → {}:{}", srv_name, target_srv, port_srv)])
                        );
                    }
                }
            }

            // CAA (Certification Authority Authorization) records via generic lookup
            if let Ok(response) = resolver.lookup(target_base, RecordType::CAA).await {
                let caas: Vec<String> = response.iter()
                    .map(|r| format!("{:?}", r))
                    .collect();
                if !caas.is_empty() {
                    let _ = tx.send(format!("[DNS Recon] CAA records: {}", caas.len())).await;
                    findings.push(
                        Finding::new(
                            target,
                            "recon",
                            "CAA (Certification Authority) Records",
                            &format!("Found {} CAA records for {}. Limits which CAs can issue certificates.", caas.len(), target_base),
                            Severity::Info,
                        ).with_confidence(0.9)
                        .with_evidence(caas)
                    );
                }
            }

            // DNSSEC status check via DNSKEY lookup
            match resolver.lookup(target_base, RecordType::DNSKEY).await {
                Ok(response) => {
                    if response.iter().next().is_some() {
                        let _ = tx.send("[DNS Recon] DNSSEC enabled — DNSKEY records found.".into()).await;
                        findings.push(
                            Finding::new(
                                target,
                                "recon",
                                "DNSSEC Enabled",
                                &format!("DNSSEC is enabled for {}. DNS responses are cryptographically signed.", target_base),
                                Severity::Info,
                            ).with_confidence(0.9)
                            .with_evidence(vec!["DNSKEY records present — DNSSEC active".into()])
                        );
                    }
                }
                Err(_) => {
                    let _ = tx.send("[DNS Recon] DNSSEC not detected.".into()).await;
                }
            }
        }

        // Generate subdomain permutations from discovered subdomains
        if resolved_count > 0 {
            let _ = tx.send("[DNS Recon] Generating subdomain permutations from discovered hosts...".into()).await;
            let permutations: Vec<String> = [
                format!("{}-dev", target_base),
                format!("{}-staging", target_base),
                format!("{}-prod", target_base),
                format!("{}-admin", target_base),
                format!("{}-backup", target_base),
                format!("{}-test", target_base),
                format!("{}-old", target_base),
                format!("{}-new", target_base),
                format!("{}-internal", target_base),
                format!("{}-external", target_base),
            ].iter().map(|s| s.to_string()).collect();
            let perm_count = discovered_subs.len().min(5);
            let extra_perms: Vec<String> = discovered_subs.iter().take(perm_count).cloned().collect();
            let mut all_perms = permutations.clone();
            all_perms.extend(extra_perms);
            for perm in &all_perms {
                let addr = format!("{}:0", perm);
                let lookup_result = tokio::time::timeout(Settings::global().dns_timeout(), lookup_host(&addr)).await;
                if let Ok(Ok(addrs)) = lookup_result {
                    let ips: Vec<String> = addrs.map(|sa| sa.ip().to_string()).collect();
                    if !ips.is_empty() {
                        let _ = tx.send(format!("[DNS Recon] Permutation: {} → {}", perm, ips.join(", "))).await;
                        findings.push(
                            Finding::new(
                                target,
                                "recon",
                                &format!("Subdomain (Permutation): {}", perm),
                                &format!("Discovered {} via subdomain permutation generation.", perm),
                                Severity::Info,
                            ).with_confidence(0.85)
                            .with_education(KnowledgeBase::for_subdomain(perm))
                            .with_evidence(vec![format!("Permutation {} → {}", perm, ips.join(", "))])
                        );
                        resolved_count += 1;
                    }
                }
            }
        }

        findings.push(
            Finding::new(
                target,
                "recon",
                "DNS Reconnaissance Complete",
                &format!("Completed DNS enumeration for {}. {} subdomains resolved out of {} checked. SRV/CAA/DNSSEC analyzed.", target, resolved_count, wordlist.len()),
                Severity::Info,
            )
            .with_confidence(1.0),
        );

        let _ = tx.send(format!(
            "[DNS Recon] Complete. Found {} subdomains (including permutations).",
            resolved_count
        )).await;

        Ok(findings)
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_subdomain_wordlist_not_empty() {
        assert!(!SUBDOMAIN_WORDLIST.is_empty());
        assert!(SUBDOMAIN_WORDLIST.len() > 100);
    }

    #[test]
    fn test_subdomain_wordlist_contains_common() {
        assert!(SUBDOMAIN_WORDLIST.contains(&"www"));
        assert!(SUBDOMAIN_WORDLIST.contains(&"mail"));
        assert!(SUBDOMAIN_WORDLIST.contains(&"admin"));
        assert!(SUBDOMAIN_WORDLIST.contains(&"api"));
    }
}
