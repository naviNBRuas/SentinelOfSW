use crate::core::config::Settings;
use crate::core::findings::{Finding, Severity};
use crate::core::knowledge::KnowledgeBase;
use crate::core::workflow::WorkflowMode;
use crate::modules::Module;
use async_trait::async_trait;
use hickory_resolver::Resolver;
use tokio::net::lookup_host;
use tokio::sync::mpsc::Sender;

const SUBDOMAIN_WORDLIST: &[&str] = &[
    "www", "mail", "admin", "vpn", "dev", "staging", "api", "blog", "cdn", "static",
    "test", "beta", "app", "web", "webmail", "portal", "intranet", "remote", "support",
    "help", "docs", "wiki", "forum", "community", "status", "git", "jenkins",
    "jira", "confluence", "grafana", "prometheus", "kibana", "elastic", "splunk",
    "nagios", "zabbix", "cacti", "chef", "ansible", "docker", "k8s",
    "kubernetes", "swagger", "graphql", "console", "monitor", "dashboard",
    "analytics", "metrics", "backup", "db", "database", "redis", "mysql",
    "mongo", "postgres", "sql", "files", "upload", "download", "assets",
    "proxy", "gateway", "auth", "login", "sso", "ldap",
    "exchange", "owa", "autodiscover", "lync", "teams", "zoom",
    "ns1", "ns2", "ns3", "smtp", "pop", "imap",
    "svn", "gitlab", "bitbucket", "nexus", "artifactory",
    "ci", "cd", "build", "deploy", "release",
    "stage", "prod", "production", "dev", "testing", "qa",
    "internal", "external", "public", "private",
    "hr", "payroll", "finance", "billing",
    "register", "signup", "signin",
    "config", "setup", "install",
    "news", "press", "careers", "about", "contact",
    "partner", "vendors",
    "s3", "bucket", "storage",
];

pub struct OsintModule;

#[async_trait]
impl Module for OsintModule {
    fn name(&self) -> &str {
        "OSINT Recon"
    }

    async fn execute_with_ports(&self, target: &str, _open_ports: &[u16], _mode: &WorkflowMode, tx: Sender<String>) -> Result<Vec<Finding>, anyhow::Error> {
        let _ = tx.send(format!("[OSINT] Starting passive reconnaissance for {}", target)).await;
        let mut findings = Vec::new();

        let target_base = if target.starts_with("http") {
            target.split("://").nth(1).and_then(|s| s.split('/').next()).unwrap_or(target)
        } else {
            target
        };
        let target_base = target_base.trim_end_matches('.');

        let is_ip = target_base.parse::<std::net::IpAddr>().is_ok();

        // 1. Reverse DNS lookup for IP targets
        if is_ip {
            let _ = tx.send(format!("[OSINT] Target is IP: {} — performing reverse DNS", target_base)).await;
            let resolver_builder = Resolver::builder_tokio();
            if let Ok(builder) = resolver_builder {
                let resolver = builder.build();
                let ip: std::net::IpAddr = target_base.parse().unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)));
                match resolver.reverse_lookup(ip).await {
                    Ok(response) => {
                        let ptrs: Vec<String> = response.iter().map(|r| r.to_string().trim_end_matches('.').to_string()).collect();
                        if !ptrs.is_empty() {
                            let _ = tx.send(format!("[OSINT] PTR records: {}", ptrs.join(", "))).await;
                            findings.push(
                                Finding::new(target, "osint", "Reverse DNS (PTR) Records",
                                    &format!("PTR records for {}: {}", target_base, ptrs.join(", ")),
                                    Severity::Info,
                                ).with_confidence(0.9).with_evidence(ptrs),
                            );
                        }
                    }
                    Err(_) => { let _ = tx.send("[OSINT] No PTR records".into()).await; }
                }
            }
        }

        let search_domain = target_base;

        // 1b. Certificate Transparency (crt.sh) — works for both domains and IPs
        let _ = tx.send(format!("[OSINT] Querying crt.sh for {}", search_domain)).await;
        let crt_url = format!("https://crt.sh/?q=%25.{}&output=json", search_domain);
        match fetch_crtsh(&crt_url).await {
            Ok(domains) if !domains.is_empty() => {
                let _ = tx.send(format!("[OSINT] crt.sh: {} hostnames found", domains.len())).await;
                findings.push(Finding::new(target, "osint", "Certificate Transparency Reconnaissance",
                    &format!("crt.sh revealed {} hostnames/domains for {}.", domains.len().min(100), search_domain),
                    Severity::Medium,
                ).with_confidence(0.85)
                .with_evidence(domains.iter().take(15).map(|d| format!("crt.sh: {}", d)).collect())
                .with_education(KnowledgeBase::for_subdomain(target_base)));
            }
            Ok(_) => { let _ = tx.send("[OSINT] crt.sh: no results".into()).await; }
            Err(e) => { let _ = tx.send(format!("[OSINT] crt.sh error: {}", e)).await; }
        }

        // DNS record enumeration (domains only)
        if !is_ip {
            let _ = tx.send("[OSINT] Resolving DNS records (MX, NS, TXT)...".into()).await;
            let resolver_builder = Resolver::builder_tokio();
            let resolver = match resolver_builder {
                Ok(builder) => builder.build(),
                Err(e) => {
                    let _ = tx.send(format!("[OSINT] DNS resolver init failed: {}", e)).await;
                    return Ok(findings);
                }
            };

            // MX records
            match resolver.mx_lookup(target_base).await {
                Ok(response) => {
                    let mxs: Vec<String> = response.iter().map(|mx| format!("{} (pref {})", mx.exchange().to_string().trim_end_matches('.'), mx.preference())).collect();
                    if !mxs.is_empty() {
                        let _ = tx.send(format!("[OSINT] MX records: {}", mxs.len())).await;
                        findings.push(Finding::new(target, "osint", "Mail Server (MX) Records",
                            &format!("Found {} MX records for {}.", mxs.len(), target_base),
                            Severity::Info,
                        ).with_confidence(0.95).with_evidence(mxs));
                    }
                }
                Err(_) => { let _ = tx.send("[OSINT] No MX records".into()).await; }
            }

            // NS records
            match resolver.ns_lookup(target_base).await {
                Ok(response) => {
                    let nss: Vec<String> = response.iter().map(|ns| ns.to_string().trim_end_matches('.').to_string()).collect();
                    if !nss.is_empty() {
                        let _ = tx.send(format!("[OSINT] NS records: {}", nss.len())).await;
                        findings.push(Finding::new(target, "osint", "Name Server (NS) Records",
                            &format!("Found {} NS records for {}.", nss.len(), target_base),
                            Severity::Info,
                        ).with_confidence(0.95).with_evidence(nss));
                    }
                }
                Err(_) => { let _ = tx.send("[OSINT] No NS records".into()).await; }
            }

            // TXT records (SPF, DKIM, DMARC)
            if let Ok(response) = resolver.txt_lookup(target_base).await {
                let txts: Vec<String> = response.iter().map(|txt| txt.to_string()).collect();
                if !txts.is_empty() {
                    let _ = tx.send(format!("[OSINT] TXT records: {}", txts.len())).await;
                    let spf = txts.iter().find(|t| t.contains("v=spf1"));
                    let has_dkim = txts.iter().any(|t| t.contains("v=DKIM1") || t.contains("o=~") || t.contains("p="));
                    if spf.is_some() || has_dkim {
                        findings.push(Finding::new(target, "osint", "Email Security (SPF/DKIM/DMARC) Records",
                            &format!("Found email security DNS records for {}. TXT count: {}", target_base, txts.len()),
                            Severity::Info,
                        ).with_confidence(0.9).with_evidence(txts.iter().take(5).cloned().collect()));
                    }
                }
            }

            // SOA record
            if let Ok(response) = resolver.soa_lookup(target_base).await {
                if let Some(soa) = response.iter().next() {
                    let _ = tx.send(format!("[OSINT] SOA: {} (admin: {})", soa.mname(), soa.rname())).await;
                }
            }

            // 3. Subdomain brute-force
            let subdomains = Settings::global().subdomain_wordlist(SUBDOMAIN_WORDLIST)
                .unwrap_or_else(|_| SUBDOMAIN_WORDLIST.iter().map(|s| s.to_string()).collect());
            let _ = tx.send(format!("[OSINT] Brute-forcing {} subdomains...", subdomains.len())).await;
            let mut subdomain_count = 0;

            for sub in &subdomains {
                let fqdn = format!("{}.{}", sub, target_base);
                let lookup_addr = format!("{}:0", fqdn);
                let addrs = tokio::time::timeout(Settings::global().dns_timeout(), lookup_host(&lookup_addr)).await;
                if let Ok(Ok(addrs)) = addrs {
                    let ips: Vec<String> = addrs.map(|sa| sa.ip().to_string()).collect();
                    if !ips.is_empty() {
                        subdomain_count += 1;
                        let _ = tx.send(format!("[OSINT] Subdomain: {} → {}", fqdn, ips.join(", "))).await;
                        if subdomain_count <= 5 {
                            findings.push(Finding::new(target, "osint", &format!("Subdomain: {}", fqdn),
                                &format!("Discovered {} resolving to {}.", fqdn, ips.join(", ")),
                                Severity::Info,
                            ).with_confidence(0.95).with_evidence(vec![format!("{} → {}", fqdn, ips.join(", "))]));
                        }
                    }
                }
            }

            if subdomain_count > 0 {
                findings.push(Finding::new(target, "osint", "Subdomain Brute-force Complete",
                    &format!("Discovered {} subdomains via brute-force wordlist.", subdomain_count),
                    Severity::Info,
                ).with_confidence(0.9));
            }
        } else {
            let _ = tx.send("[OSINT] Target is IP — DNS record enumeration skipped (PTR lookup above)".into()).await;
        }

        let _ = tx.send(format!("[OSINT] Complete. {} findings.", findings.len())).await;
        Ok(findings)
    }
}

fn parse_crt_json(text: &str) -> Result<Vec<String>, anyhow::Error> {
    let entries: Vec<serde_json::Value> = serde_json::from_str(text)?;
    let mut domains = Vec::new();
    for entry in entries {
        if let Some(name_value) = entry.get("name_value").and_then(|v| v.as_str()) {
            for line in name_value.lines() {
                let trimmed = line.trim().trim_end_matches('.');
                if !trimmed.is_empty() && !domains.contains(&trimmed.to_string()) {
                    domains.push(trimmed.to_string());
                }
            }
        }
    }
    domains.sort();
    domains.dedup();
    Ok(domains)
}

async fn fetch_crtsh(url: &str) -> Result<Vec<String>, anyhow::Error> {
    let mut builder = reqwest::Client::builder()
        .timeout(Settings::global().http_timeout())
        .user_agent(Settings::global().osint_user_agent());
    if let Some(proxy_url) = Settings::global().proxy_url() {
        if let Ok(proxy) = reqwest::Proxy::all(proxy_url) {
            builder = builder.proxy(proxy);
        }
    }
    let client = builder.build()?;

    let resp = client.get(url).send().await?;
    if !resp.status().is_success() {
        return Err(anyhow::anyhow!("crt.sh returned {}", resp.status()));
    }

    let text = resp.text().await?;
    parse_crt_json(&text)
}

#[cfg(test)]
mod tests {
    use super::parse_crt_json;

    #[test]
    fn test_parse_crt_response_empty() {
        let result = parse_crt_json("[]");
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn test_parse_crt_response_not_json() {
        let result = parse_crt_json("not json");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_crt_response_basic() {
        let json = r#"[
            {"name_value": "*.example.com\nsub.example.com"},
            {"name_value": "mail.example.com"}
        ]"#;
        let result = parse_crt_json(json).unwrap();
        assert!(result.contains(&"*.example.com".to_string()));
        assert!(result.contains(&"sub.example.com".to_string()));
        assert!(result.contains(&"mail.example.com".to_string()));
        assert_eq!(result.len(), 3);
    }

    #[test]
    fn test_parse_crt_response_deduplication() {
        let json = r#"[
            {"name_value": "test.example.com"},
            {"name_value": "test.example.com"},
            {"name_value": "other.example.com"}
        ]"#;
        let result = parse_crt_json(json).unwrap();
        assert_eq!(result.len(), 2);
    }
}
