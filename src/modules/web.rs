use crate::core::adaptive::{parse_env_secrets, parse_git_config_creds, Credential, Intent, ScanContext};
use crate::core::config::Settings;
use crate::core::docker::global_docker;
use crate::core::findings::{Finding, Severity};
use crate::core::knowledge::KnowledgeBase;
use crate::core::tools::{run_ffuf, run_nikto, run_sslscan};
use crate::core::workflow::WorkflowMode;
use crate::modules::Module;
use async_trait::async_trait;
use reqwest::Client;
use reqwest::redirect::Policy;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc::Sender;
use tokio::sync::Semaphore;

const DIR_WORDLIST: &[&str] = &[
    "admin", "administrator", "backup", "backups", "bak", "config", "configuration",
    "conf", "data", "db", "database", "debug", "default", "dev", "docs", "download",
    "error", "errors", "etc", "export", "files", "ftp", "git", "home", "htdocs",
    "images", "img", "include", "includes", "index", "install", "js", "json",
    "lib", "library", "libraries", "log", "logs", "login", "logout", "mail",
    "manager", "media", "misc", "modules", "mysql", "network", "old", "panel",
    "password", "php", "phpmyadmin", "pma", "private", "public", "reports",
    "robots.txt", "sass", "scripts", "search", "secure", "security", "server",
    "service", "services", "setup", "signin", "signup", "site", "sitemap.xml",
    "sql", "src", "ssh", "ssl", "status", "storage", "support", "swagger",
    "swagger-ui", "swagger.json", "swagger.yaml", "system", "templates", "test",
    "tmp", "tools", "upload", "uploads", "user", "users", "vendor", "version",
    "web", "webroot", "webapp", "www", "xml", ".env", ".git/HEAD", ".svn",
    ".htaccess", ".htpasswd", "wp-admin", "wp-content", "wp-includes",
    "wp-json", "wp-login.php", "administrator", "joomla", "drupal",
    "api", "api/v1", "api/v2", "graphql", "rest", "soap", "xmlrpc.php",
    "cgi-bin", "cpanel", "plesk", "webmin", "server-status",
    "server-info", "crossdomain.xml", "clientaccesspolicy.xml",
    ".well-known", "security.txt", "humans.txt", "ads.txt",
];

const CTF_FILES: &[&str] = &[
    "/flag.txt", "/flag", "/flag.php", "/.flag", "/flag.html",
    "/robots.txt", "/.git/config", "/.gitignore", "/.htpasswd",
    "/admin.php", "/admin.html", "/login.php", "/login.html",
    "/config.php", "/config.php.bak", "/config.php~",
    "/index.php.bak", "/index.php~", "/index.html.bak",
    "/backup.sql", "/db.sql", "/dump.sql", "/database.sql",
    "/wp-config.php", "/wp-config.php.bak",
    "/shell.php", "/cmd.php", "/exec.php",
    "/test.php", "/info.php", "/phpinfo.php",
    "/.env", "/env", "/environment",
    "/api/flag", "/api/v1/flag", "/graphql",
    "/swagger.json", "/swagger.yaml", "/api-docs",
    "/debug", "/trace", "/.idea/workspace.xml",
    "/note.txt", "/notes.txt", "/todo.txt", "/hint.txt",
    "/password.txt", "/passwords.txt", "/creds.txt",
    "/secret.txt", "/secret", "/hidden",
    "/.hidden", "/private", "/.private",
    "/tmp", "/temp", "/uploads",
];

fn build_client() -> Client {
    let mut builder = Client::builder()
        .timeout(Settings::global().http_timeout())
        .redirect(Policy::none())
        .danger_accept_invalid_certs(true)
        .user_agent(Settings::global().user_agent());
    if let Some(proxy_url) = Settings::global().proxy_url() {
        if let Ok(proxy) = reqwest::Proxy::all(proxy_url) {
            builder = builder.proxy(proxy);
        }
    }
    builder
        .build()
        .expect("Failed to build reqwest client")
}

fn extract_disallowed_paths(body: &str) -> Vec<String> {
    body.lines()
        .filter(|l| l.to_lowercase().starts_with("disallow:"))
        .filter_map(|l| l.split_once(':').map(|(_, v)| v))
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

pub struct WebEnum;

#[async_trait]
impl Module for WebEnum {
    fn name(&self) -> &str {
        "Web Enumeration"
    }

    async fn execute_with_ports(&self, target: &str, open_ports: &[u16], mode: &WorkflowMode, tx: Sender<String>) -> Result<Vec<Finding>, anyhow::Error> {
        let _ = tx.send(format!("[Web Enum] Starting web enumeration for {}", target)).await;
        let mut findings = Vec::new();
        let client = Arc::new(build_client());

        let dirs = Settings::global().directory_wordlist(DIR_WORDLIST)
            .unwrap_or_else(|_| DIR_WORDLIST.iter().map(|s| s.to_string()).collect());
        let ctf_files = Settings::global().ctf_file_wordlist(CTF_FILES)
            .unwrap_or_else(|_| CTF_FILES.iter().map(|s| s.to_string()).collect());

        let web_services: Vec<String> = if target.starts_with("http") {
            vec![target.to_string()]
        } else {
            let common_web_ports: &[u16] = &[80, 443, 8080, 8443, 8000, 3000, 5000, 8888, 9090];
            let mut web_ports: Vec<u16> = open_ports.iter().copied().filter(|p| !common_web_ports.contains(p)).collect();
            web_ports.extend_from_slice(common_web_ports);
            web_ports.dedup();
            let mut found = Vec::new();

            for &port in &web_ports {
                let url = if port == 443 || port == 8443 {
                    format!("https://{}:{}", target, port)
                } else {
                    format!("http://{}:{}", target, port)
                };
                let _ = tx.send(format!("[Web Enum] Trying {}", url)).await;
                match client.get(&url).send().await {
                    Ok(resp) if resp.status().as_u16() < 400 || resp.status().as_u16() == 403 || resp.status().as_u16() == 401 => {
                        let _ = tx.send(format!("[Web Enum] Found web service at {} (status {})", url, resp.status())).await;
                        found.push(url);
                    }
                    Ok(resp) => {
                        let _ = tx.send(format!("[Web Enum] {} returned {}", url, resp.status())).await;
                    }
                    Err(_) => continue,
                }
            }

            if found.is_empty() {
                let _ = tx.send("[Web Enum] No web service found on common ports".into()).await;
                vec![format!("http://{}:80", target)]
            } else {
                found
            }
        };

        let base = web_services[0].trim_end_matches('/');

        // Iterate over all discovered web services for directory/CTF scans
        for service_url in &web_services {
            let service_base = service_url.trim_end_matches('/');
            let _ = tx.send(format!("[Web Enum] Scanning {}...", service_base)).await;

            // Check robots.txt
            let robots_url = format!("{}/robots.txt", service_base);
            match client.get(&robots_url).send().await {
                Ok(resp) if resp.status().as_u16() == 200 => {
                    let body = resp.text().await.unwrap_or_default();
                    let disallowed: Vec<String> = extract_disallowed_paths(&body);
                    let _ = tx.send(format!("[Web Enum] robots.txt found with {} disallowed paths", disallowed.len())).await;
                    findings.push(
                        Finding::new(target, "web", "Robots.txt Discovered",
                            &format!("robots.txt found at {} with {} disallowed paths.", service_base, disallowed.len()),
                            Severity::Info,
                        ).with_confidence(0.95)
                        .with_education(KnowledgeBase::for_robots_txt(&disallowed))
                        .with_evidence(vec![format!("robots.txt: {}", body.lines().take(10).collect::<Vec<_>>().join("\n"))]),
                    );
                }
                _ => {}
            }

            // Concurrent directory enumeration using full wordlist
            let _ = tx.send(format!("[Web Enum] Directory enumeration on {} ({} paths, concurrency={})", service_base, dirs.len(), Settings::global().web_semaphore())).await;
            let sem = Arc::new(Semaphore::new(Settings::global().web_semaphore()));
            let mut handles = Vec::new();

            for dir in &dirs {
                let url = format!("{}/{}", service_base, dir);
                let client = Arc::clone(&client);
                let tx = tx.clone();
                let sem = Arc::clone(&sem);
                let dir = dir.clone();

                handles.push(tokio::spawn(async move {
                    let _permit = sem.acquire().await.unwrap();
                    let result = client.get(&url).send().await;
                    drop(_permit);
                    match result {
                        Ok(resp) => {
                            let status = resp.status().as_u16();
                            if status == 200 || status == 301 || status == 302 || status == 403 || status == 401 {
                                let _ = tx.send(format!("[Web Enum] Found: {} → {}", url, status)).await;
                                Some((dir, status))
                            } else {
                                None
                            }
                        }
                        Err(_) => None,
                    }
                }));
            }

            for handle in handles {
                if let Some((dir, status)) = handle.await.unwrap_or(None) {
                    findings.push(
                        Finding::new(
                            target, "web",
                            &format!("Discovered Path: /{}", dir),
                            &format!("Found accessible path /{} on {} (HTTP {}).", dir, service_base, status),
                            match dir.as_str() {
                                ".git" | ".env" | "backup" | "backups" => Severity::High,
                                "admin" | "wp-admin" | "phpmyadmin" | "panel" | "login" | "config" => Severity::Medium,
                                _ => Severity::Low,
                            },
                        ).with_confidence(0.9)
                        .with_education(KnowledgeBase::for_directory_listing())
                        .with_evidence(vec![format!("GET {}/{} returned HTTP {}", service_base, dir, status)]),
                    );
                }
            }

        // Tech stack detection
        let root_url = format!("{}/", base);
        match client.get(&root_url).send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let server = resp.headers().get("server").and_then(|v| v.to_str().ok()).map(|s| s.to_string());
                let powered_by = resp.headers().get("x-powered-by").and_then(|v| v.to_str().ok()).map(|s| s.to_string());

                if let Some(ref srv) = server {
                    let _ = tx.send(format!("[Web Enum] Server: {}", srv)).await;
                    let cve_info = match srv.to_lowercase().as_str() {
                        s if s.contains("apache/2.4.49") => Some(("CVE-2021-41773", "Apache HTTP Server 2.4.49 is vulnerable to path traversal (CVE-2021-41773).")),
                        s if s.contains("apache/2.4.50") => Some(("CVE-2021-42013", "Apache HTTP Server 2.4.50 is vulnerable to path traversal (CVE-2021-42013).")),
                        s if s.contains("iis/6.0") => Some(("CVE-2017-7269", "IIS 6.0 vulnerable to WebDAV buffer overflow.")),
                        s if s.contains("iis/7.5") => Some(("CVE-2010-3972", "IIS 7.5 vulnerable to FTP service buffer overflow.")),
                        s if s.contains("nginx/1.") && s < "nginx/1.20" => Some(("CVE-2021-23017", "Older nginx has DNS resolution vulnerability.")),
                        _ => None,
                    };

                    let mut finding = Finding::new(target, "web",
                        &format!("Web Server: {}", srv),
                        &format!("HTTP server: {} (status {}).", srv, status),
                        if cve_info.is_some() { Severity::High } else { Severity::Info },
                    ).with_confidence(0.95)
                    .with_evidence(vec![format!("Server: {}", srv)]);

                    if let Some((cve, desc)) = cve_info {
                        finding = finding.with_education(KnowledgeBase::for_cve(cve, desc)).with_cve(cve);
                    }
                    findings.push(finding);
                }

                if let Some(ref pb) = powered_by {
                    let _ = tx.send(format!("[Web Enum] X-Powered-By: {}", pb)).await;
                }

                // Security headers check
                let headers = resp.headers();
                let mut missing_headers = Vec::new();
                for (key, name) in &[("x-frame-options", "X-Frame-Options"), ("x-content-type-options", "X-Content-Type-Options"),
                    ("strict-transport-security", "Strict-Transport-Security"), ("content-security-policy", "Content-Security-Policy"),
                    ("x-xss-protection", "X-XSS-Protection"), ("referrer-policy", "Referrer-Policy"),
                    ("permissions-policy", "Permissions-Policy"), ("cross-origin-opener-policy", "Cross-Origin-Opener-Policy")] {
                    if !headers.contains_key(*key) { missing_headers.push(*name); }
                }
                if !missing_headers.is_empty() {
                    findings.push(
                        Finding::new(target, "web", "Missing Security Headers",
                            &format!("Missing {} common security headers: {}", missing_headers.len(), missing_headers.join(", ")),
                            Severity::Low,
                        ).with_confidence(0.9),
                    );
                }

                // WebSocket support detection
                {
                    let upgrade = resp.headers().get("upgrade").and_then(|v| v.to_str().ok());
                    let connection = resp.headers().get("connection").and_then(|v| v.to_str().ok());
                    if let Some(upg) = upgrade {
                        if upg.to_lowercase() == "websocket" || connection.is_some_and(|c| c.to_lowercase().contains("upgrade")) {
                            let _ = tx.send(format!("[Web Enum] WebSocket supported at {}", service_base)).await;
                            findings.push(
                                Finding::new(target, "web", "WebSocket Endpoint Detected",
                                    &format!("WebSocket upgrade is supported at {}. May allow real-time communication exploits.", service_base),
                                    Severity::Low,
                                ).with_confidence(0.8)
                                .with_evidence(vec![format!("WebSocket upgrade header at {}", service_base)]),
                            );
                        }
                    }
                }

                // TLS certificate analysis (for HTTPS services)
                if service_base.starts_with("https") {
                    let _ = tx.send(format!("[Web Enum] Checking TLS certificate for {}...", service_base)).await;
                    let port: u16 = service_base.rsplit(':').next()
                        .and_then(|s| s.trim_end_matches('/').parse().ok())
                        .unwrap_or(443);
                    if let Some(docker) = global_docker() {
                        let ssl_result = run_sslscan(target, port, Some(docker), 30).await;
                        if !ssl_result.stdout.is_empty() {
                            let cert_info: Vec<&str> = ssl_result.stdout.lines()
                                .filter(|l| l.contains("Subject:") || l.contains("Issuer:") || l.contains("Not valid") || l.contains("Self-signed") || l.contains("TLS") || l.contains("SSL"))
                                .collect();
                            for line in &cert_info {
                                let _ = tx.send(format!("[Web Enum] sslscan: {}", line.trim())).await;
                            }
                            let self_signed = cert_info.iter().any(|l| l.to_lowercase().contains("self-signed"));
                            let expired = cert_info.iter().any(|l| l.to_lowercase().contains("expired"));
                            if self_signed || expired {
                                let sev = if expired { Severity::High } else { Severity::Medium };
                                findings.push(
                                    Finding::new(target, "web",
                                        if expired {"TLS Certificate: Expired"} else {"TLS Certificate: Self-Signed"},
                                        &format!("TLS certificate issue detected on {}: {}", port, cert_info.join("; ")),
                                        sev,
                                    ).with_confidence(0.9)
                                    .with_evidence(cert_info.iter().take(5).map(|l| format!("sslscan: {}", l)).collect()),
                                );
                            }
                        }
                    }
                }

                // CMS Fingerprinting
                let body = resp.text().await.unwrap_or_default();
                let body_lower = body.to_lowercase();
                let mut cms_hits = Vec::new();
                if body_lower.contains("wp-content") || body_lower.contains("wp-json") || body_lower.contains("wordpress") || body_lower.contains("/wp-") {
                    cms_hits.push("WordPress");
                }
                if body_lower.contains("joomla!") || body_lower.contains("joomla") || body_lower.contains("com_content") || body_lower.contains("com_modules") {
                    cms_hits.push("Joomla");
                }
                if body_lower.contains("drupal") || body_lower.contains("drupal.js") || body_lower.contains("sites/default") || body_lower.contains("core/themes") {
                    cms_hits.push("Drupal");
                }
                if body_lower.contains("magento") || body_lower.contains("skin/frontend") || body_lower.contains("mage/") {
                    cms_hits.push("Magento");
                }
                if body_lower.contains("shopify") || body_lower.contains("myshopify") || body_lower.contains("cdn.shopify") {
                    cms_hits.push("Shopify");
                }
                if body_lower.contains("laravel") || body_lower.contains("csrf-token") && body_lower.contains("__token") {
                    cms_hits.push("Laravel");
                }
                if body_lower.contains("django") || body_lower.contains("csrftoken") || body_lower.contains("django-admin") {
                    cms_hits.push("Django");
                }
                if body_lower.contains("asp.net") || body_lower.contains("__viewstate") || body_lower.contains("__requestverificationtoken") {
                    cms_hits.push("ASP.NET");
                }
                for cms in &cms_hits {
                    let _ = tx.send(format!("[Web Enum] CMS detected: {}", cms)).await;
                    findings.push(
                        Finding::new(target, "web",
                            &format!("CMS Detected: {}", cms),
                            &format!("The web application appears to be running {}. Consider version-specific enumeration and known CVEs.", cms),
                            Severity::Info,
                        ).with_confidence(0.7)
                        .with_evidence(vec![format!("CMS {} detected via HTTP response markers", cms)]),
                    );
                }
            }
            Err(e) => {
                let _ = tx.send(format!("[Web Enum] Root check error: {}", e)).await;
            }
        }

        // Docker-powered enumeration with ffuf/gobuster/nikto
        if let Some(docker) = global_docker() {
            let docker = docker as &crate::core::docker::DockerManager;
            let _ = tx.send("[Web Enum] Docker available — running ffuf/gobuster/nikto scans".into()).await;

            // Extract port from first web service for tool arguments
            let web_port: u16 = web_services[0].rsplit(':').next()
                .and_then(|s| s.trim_end_matches('/').parse().ok())
                .unwrap_or(80);

            // ffuf directory scan — use container wordlists
            let ffuf_wordlist = if matches!(mode, WorkflowMode::Ctf) {
                // Kali container paths after installing dirbuster/dirb
                "/usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt"
            } else {
                "/usr/share/dirb/wordlists/common.txt"
            };
            let _ = tx.send(format!("[Web Enum] Running ffuf on port {}...", web_port)).await;
            let ffuf_result = run_ffuf(target, web_port, ffuf_wordlist, Some(docker), 120).await;
            if !ffuf_result.stdout.is_empty() {
                for line in ffuf_result.stdout.lines().take(50) {
                    if line.contains("Status: 200") || line.contains("Status: 301") || line.contains("Status: 403") {
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        if let Some(path) = parts.iter().find(|p| p.starts_with("/") || p.starts_with("FUZZ")) {
                            let path = path.trim_start_matches("FUZZ");
                            let status = parts.iter().filter_map(|p| p.strip_prefix("Status:").or_else(|| p.strip_prefix("Size:").or_else(|| p.strip_prefix("Lines:"))).and_then(|s| s.trim().parse::<u16>().ok())).next().unwrap_or(200);
                            let _ = tx.send(format!("[Web Enum] ffuf discovered: {}{}", if path.starts_with('/') { "" } else { "/" }, path)).await;
                            findings.push(
                                Finding::new(target, "web",
                                    &format!("Discovered Path (ffuf): /{}", path.trim_start_matches('/')),
                                    &format!("Found via ffuf directory scan (HTTP {}).", status),
                                    Severity::Low,
                                ).with_confidence(0.85)
                                .with_evidence(vec![format!("ffuf: /{} returned HTTP {}", path.trim_start_matches('/'), status)]),
                            );
                        }
                    }
                }
            }

            // nikto web vulnerability scan in CTF mode
            if matches!(mode, WorkflowMode::Ctf) {
                let _ = tx.send(format!("[Web Enum] Running nikto on port {}...", web_port)).await;
                let nikto_result = run_nikto(target, web_port, Some(docker), 180).await;
                let mut vuln_count = 0;
                for line in nikto_result.stdout.lines() {
                    if line.contains("+ ") && (line.contains("vulnerable") || line.contains("OSVDB") || line.contains("CVE-") || line.contains("DISCLOSURE")) {
                        vuln_count += 1;
                        if vuln_count <= 10 {
                            let _ = tx.send(format!("[Web Enum] Nikto: {}", line.trim())).await;
                        }
                    }
                }
                if vuln_count > 0 {
                    findings.push(
                        Finding::new(target, "web",
                            &format!("Nikto found {} potential issues", vuln_count),
                            "Nikto web scanner identified potential vulnerabilities.",
                            Severity::Medium,
                        ).with_confidence(0.7)
                        .with_evidence(vec![format!("Nikto reported {} potential vulnerabilities", vuln_count)]),
                    );
                }
            }
        }

            // CTF-specific aggressive enumeration
            if matches!(mode, WorkflowMode::Ctf) {
                let _ = tx.send(format!("[Web Enum] CTF mode: checking {} flag/path files on {}", ctf_files.len(), service_base)).await;
                let sem = Arc::new(Semaphore::new(Settings::global().web_semaphore()));
                let mut handles = Vec::new();

                for file in &ctf_files {
                    let url = if file.starts_with('/') {
                        format!("{}{}", service_base, file)
                    } else {
                        format!("{}/{}", service_base, file)
                    };
                    let client = Arc::clone(&client);
                    let tx = tx.clone();
                    let sem = Arc::clone(&sem);
                    let file = file.clone();

                    handles.push(tokio::spawn(async move {
                        let _permit = sem.acquire().await.unwrap();
                        let result = client.get(&url).send().await;
                        drop(_permit);
                        match result {
                            Ok(resp) if resp.status().as_u16() == 200 => {
                                let body = resp.text().await.unwrap_or_default();
                                let preview = body.chars().take(300).collect::<String>();
                                let _ = tx.send(format!("[Web Enum] CTF: {} (200, {} bytes)", url, body.len())).await;
                                Some((url, file, preview, body.len()))
                            }
                            _ => None,
                        }
                    }));
                }

                for handle in handles {
                    if let Some((url, file, preview, size)) = handle.await.unwrap_or(None) {
                        // Flag regex hunting on response body
                        let flag_patterns = [
                            (r"HTB\{[^}]+\}", "HTB"),
                            (r"flag\{[^}]+\}", "flag"),
                            (r"FLAG\{[^}]+\}", "FLAG"),
                            (r"CTF\{[^}]+\}", "CTF"),
                            (r"SKY\{[^}]+\}", "SKY"),
                            (r"THM\{[^}]+\}", "THM"),
                        ];
                        let mut found_flags: Vec<String> = Vec::new();
                        for (pattern, name) in &flag_patterns {
                            if let Ok(re) = regex::Regex::new(pattern) {
                                for cap in re.captures_iter(&preview) {
                                    if let Some(mat) = cap.get(0) {
                                        let flag = mat.as_str().to_string();
                                        if !found_flags.iter().any(|f| flag.starts_with(f) || f.starts_with(&flag)) {
                                            found_flags.push(flag.clone());
                                            let _ = tx.send(format!("[Web Enum] FLAG FOUND: {} in {}: {}", name, file, flag)).await;
                                            findings.push(
                                                Finding::new(target, "web",
                                                    &format!("FLAG FOUND: {} in {}", flag, file),
                                                    &format!("Found flag matching {} pattern in {}. Flag: {}", name, file, flag),
                                                    Severity::Critical,
                                                ).with_confidence(1.0)
                                                .with_evidence(vec![format!("Flag {} discovered in {}", flag, file)]),
                                            );
                                        }
                                    }
                                }
                            }
                        }

                        let sev = if !found_flags.is_empty() || file.contains("flag") || file.contains("shell") { Severity::Critical }
                                  else if file.contains("config") || file.contains("backup") || file.contains(".git") { Severity::High }
                                  else { Severity::Medium };
                        if found_flags.is_empty() {
                            findings.push(
                                Finding::new(target, "web",
                                    &format!("CTF Discovery: {}", file),
                                    &format!("Found CTF file {} ({} bytes). Preview: {}", file, size, preview),
                                    sev,
                                ).with_confidence(0.9)
                                .with_evidence(vec![format!("GET {} returned HTTP 200 ({} bytes)", url, size)]),
                            );
                        }
                    }
                }
            }
        }

        let _ = tx.send(format!("[Web Enum] Complete. {} findings.", findings.len())).await;
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
        let Intent::SecretHarvest { urls } = intent else {
            return self.execute_with_ports(target, open_ports, mode, tx).await;
        };

        // Fetch each already-exposed file and parse it for credentials, which we
        // publish to the shared context so the engine can chain credential reuse.
        let client = build_client();
        let mut findings = Vec::new();
        for url in urls {
            let _ = tx.send(format!("[Web Enum] Harvesting secrets from {}", url)).await;
            let body = match client.get(url).send().await {
                Ok(resp) if resp.status().is_success() => resp.text().await.unwrap_or_default(),
                Ok(resp) => {
                    let _ = tx.send(format!("[Web Enum] {} returned HTTP {}", url, resp.status().as_u16())).await;
                    continue;
                }
                Err(e) => {
                    let _ = tx.send(format!("[Web Enum] Harvest failed for {}: {}", url, e)).await;
                    continue;
                }
            };

            let lower = url.to_ascii_lowercase();
            let mut harvested: Vec<Credential> = Vec::new();
            if lower.contains(".git/config") {
                for (user, pass) in parse_git_config_creds(&body) {
                    harvested.push(Credential {
                        service: "VCS".into(),
                        port: 0,
                        user,
                        pass,
                        source: format!(".git/config@{}", url),
                    });
                }
            } else {
                for (key, user, pass) in parse_env_secrets(&body) {
                    findings.push(
                        Finding::new(
                            target,
                            "web",
                            &format!("Leaked Secret: {}", key),
                            &format!("Exposed file {} leaks secret '{}'. Secrets in served files enable credential theft.", url, key),
                            Severity::High,
                        )
                        .with_confidence(0.9)
                        .with_evidence(vec![format!("{} contains {}=<redacted len {}>", url, key, pass.len())]),
                    );
                    if !pass.is_empty() {
                        harvested.push(Credential {
                            service: "env".into(),
                            port: 0,
                            user: user.clone(),
                            pass,
                            source: format!(".env@{}", url),
                        });
                    }
                }
            }

            if !harvested.is_empty() {
                let _ = tx.send(format!("[Web Enum] Harvested {} credential(s) from {}", harvested.len(), url)).await;
                if let Ok(mut c) = ctx.lock() {
                    c.loot.push(url.clone());
                    for cred in harvested {
                        c.add_credential(cred);
                    }
                }
            }
        }

        let _ = tx.send(format!("[Web Enum] Harvest complete. {} secret finding(s).", findings.len())).await;
        Ok(findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_disallowed_paths_preserves_colons() {
        let body = "User-agent: *\nDisallow: /search?url=http://evil.com\nAllow: /\n";
        let paths = extract_disallowed_paths(body);
        assert_eq!(paths, vec!["/search?url=http://evil.com"]);
    }

    #[test]
    fn test_extract_disallowed_paths_basic_and_case_insensitive() {
        let body = "User-agent: *\ndisallow: /admin\nDisallow:/secret\nDisallow: /backup/\n";
        let paths = extract_disallowed_paths(body);
        assert_eq!(paths, vec!["/admin", "/secret", "/backup/"]);
    }

    #[test]
    fn test_extract_disallowed_paths_skips_empty_values() {
        let body = "Disallow:\nDisallow: \nDisallow: /real\n";
        let paths = extract_disallowed_paths(body);
        assert_eq!(paths, vec!["/real"]);
    }

    #[test]
    fn test_extract_disallowed_paths_ignores_non_disallow_lines() {
        let body = "User-agent: Googlebot\nCrawl-delay: 10\nSitemap: https://x/sitemap.xml\n";
        assert!(extract_disallowed_paths(body).is_empty());
    }
}
