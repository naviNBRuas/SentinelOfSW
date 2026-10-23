#![allow(dead_code)]

use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::Path;
use std::sync::{Mutex, OnceLock};

/// Runtime CLI overrides that take precedence over settings.toml
pub static RUNTIME_OVERRIDES: OnceLock<Mutex<RuntimeOverrides>> = OnceLock::new();

#[derive(Debug, Clone, Default)]
pub struct RuntimeOverrides {
    pub exclude_ports: Vec<u16>,
    pub stealth_mode: bool,
    pub no_report: bool,
    pub json_mode: bool,
    pub threads: Option<usize>,
    pub rate_limit: Option<u64>,
    pub timeout: Option<u64>,
}

impl RuntimeOverrides {
    pub fn global() -> std::sync::MutexGuard<'static, RuntimeOverrides> {
        RUNTIME_OVERRIDES.get_or_init(|| Mutex::new(RuntimeOverrides::default())).lock().unwrap()
    }

    pub fn set(overrides: RuntimeOverrides) {
        *RUNTIME_OVERRIDES.get_or_init(|| Mutex::new(RuntimeOverrides::default())).lock().unwrap() = overrides;
    }

    pub fn update<F: FnOnce(&mut RuntimeOverrides)>(f: F) {
        f(&mut RUNTIME_OVERRIDES.get_or_init(|| Mutex::new(RuntimeOverrides::default())).lock().unwrap());
    }
}

static GLOBAL_CONFIG: OnceLock<Settings> = OnceLock::new();

#[derive(Debug, Clone, Deserialize)]
pub struct Settings {
    #[serde(default)]
    pub ports: PortConfig,
    #[serde(default)]
    pub timeouts: TimeoutConfig,
    #[serde(default)]
    pub concurrency: ConcurrencyConfig,
    #[serde(default)]
    pub scan: ScanConfig,
    #[serde(default = "default_wordlist_subdomains")]
    pub wordlist_subdomains_file: String,
    #[serde(default = "default_wordlist_directories")]
    pub wordlist_directories_file: String,
    #[serde(default = "default_wordlist_ctf")]
    pub wordlist_ctf_files_file: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PortConfig {
    #[serde(default = "default_ports_default")]
    pub default: Vec<PortEntry>,
    #[serde(default = "default_ports_ctf")]
    pub ctf: Vec<PortEntry>,
    #[serde(default = "default_ports_quick")]
    pub quick: Vec<u16>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum PortEntry {
    Single(u16),
    Range(PortRange),
}

#[derive(Debug, Clone, Deserialize)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TimeoutConfig {
    #[serde(default = "default_connect_ms")]
    pub connect_ms: u64,
    #[serde(default = "default_ctf_connect_ms")]
    pub ctf_connect_ms: u64,
    #[serde(default = "default_http_secs")]
    pub http_secs: u64,
    #[serde(default = "default_dns_secs")]
    pub dns_secs: u64,
    #[serde(default = "default_banner_secs")]
    pub banner_secs: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ConcurrencyConfig {
    #[serde(default = "default_port_scan_batch")]
    pub port_scan_batch: usize,
    #[serde(default = "default_port_scan_ctf_batch")]
    pub port_scan_ctf_batch: usize,
    #[serde(default = "default_dns_semaphore")]
    pub dns_semaphore: usize,
    #[serde(default = "default_web_semaphore")]
    pub web_semaphore: usize,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ScanConfig {
    #[serde(default = "default_report_path")]
    pub report_path: String,
    #[serde(default = "default_user_agent")]
    pub user_agent: String,
    #[serde(default = "default_osint_ua")]
    pub osint_user_agent: String,
    #[serde(default)]
    pub proxy_url: String,
    #[serde(default)]
    pub docker_enabled: bool,
    #[serde(default = "default_docker_image")]
    pub docker_image: String,
    #[serde(default)]
    pub vpn_config: String,
    #[serde(default)]
    pub exclude_ports: String,
    #[serde(default)]
    pub no_report: bool,
    #[serde(default)]
    pub stealth_mode: bool,
}

impl Settings {
    pub fn global() -> &'static Settings {
        GLOBAL_CONFIG.get_or_init(Self::default)
    }

    pub fn load(path: &str) -> Result<()> {
        let content = std::fs::read_to_string(path)?;
        let settings: Settings = toml::from_str(&content)?;
        GLOBAL_CONFIG.set(settings).ok();
        Ok(())
    }

    pub fn try_load(path: &str) -> Result<bool> {
        if Path::new(path).exists() {
            Self::load(path)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub fn resolve_ports_default(&self) -> Vec<u16> {
        self.ports.default.iter().flat_map(|e| e.expand()).collect()
    }

    pub fn resolve_ports_ctf(&self) -> Vec<u16> {
        self.ports.ctf.iter().flat_map(|e| e.expand()).collect()
    }

    pub fn resolve_ports_quick(&self) -> Vec<u16> {
        self.ports.quick.clone()
    }

    pub fn load_wordlist(&self, file_path: &str, builtin: &[&str]) -> Result<Vec<String>> {
        if file_path.is_empty() || !Path::new(file_path).exists() {
            return Ok(builtin.iter().map(|s| s.to_string()).collect());
        }
        let content = std::fs::read_to_string(file_path)
            .with_context(|| format!("Failed to read wordlist: {}", file_path))?;
        Ok(content.lines().filter(|l| !l.is_empty()).map(|l| l.to_string()).collect())
    }

    pub fn connect_timeout(&self) -> std::time::Duration {
        std::time::Duration::from_millis(self.timeouts.connect_ms)
    }

    pub fn ctf_connect_timeout(&self) -> std::time::Duration {
        std::time::Duration::from_millis(self.timeouts.ctf_connect_ms)
    }

    pub fn http_timeout(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.timeouts.http_secs)
    }

    pub fn dns_timeout(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.timeouts.dns_secs)
    }

    pub fn banner_timeout(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.timeouts.banner_secs)
    }

    pub fn port_scan_concurrency(&self) -> usize {
        self.concurrency.port_scan_batch
    }

    pub fn port_scan_ctf_concurrency(&self) -> usize {
        self.concurrency.port_scan_ctf_batch
    }

    pub fn dns_semaphore(&self) -> usize {
        self.concurrency.dns_semaphore
    }

    pub fn web_semaphore(&self) -> usize {
        self.concurrency.web_semaphore
    }

    pub fn report_path(&self) -> &str {
        &self.scan.report_path
    }

    pub fn user_agent(&self) -> &str {
        &self.scan.user_agent
    }

    pub fn osint_user_agent(&self) -> &str {
        &self.scan.osint_user_agent
    }

    pub fn subdomain_wordlist(&self, builtin: &[&str]) -> Result<Vec<String>> {
        self.load_wordlist(&self.wordlist_subdomains_file, builtin)
    }

    pub fn directory_wordlist(&self, builtin: &[&str]) -> Result<Vec<String>> {
        self.load_wordlist(&self.wordlist_directories_file, builtin)
    }

    pub fn ctf_file_wordlist(&self, builtin: &[&str]) -> Result<Vec<String>> {
        self.load_wordlist(&self.wordlist_ctf_files_file, builtin)
    }

    pub fn proxy_url(&self) -> Option<&str> {
        let u = self.scan.proxy_url.trim();
        if u.is_empty() { None } else { Some(u) }
    }

    pub fn docker_enabled(&self) -> bool {
        self.scan.docker_enabled
    }

    pub fn docker_image(&self) -> &str {
        &self.scan.docker_image
    }

    pub fn vpn_config(&self) -> Option<&str> {
        let v = self.scan.vpn_config.trim();
        if v.is_empty() { None } else { Some(v) }
    }

    pub fn excluded_ports(&self) -> Vec<u16> {
        self.scan.exclude_ports.split(',')
            .filter_map(|s| s.trim().parse::<u16>().ok())
            .collect()
    }

    pub fn no_report(&self) -> bool {
        self.scan.no_report
    }

    pub fn stealth_mode(&self) -> bool {
        self.scan.stealth_mode
    }
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            report_path: default_report_path(),
            user_agent: default_user_agent(),
            osint_user_agent: default_osint_ua(),
            proxy_url: String::new(),
            docker_enabled: false,
            docker_image: default_docker_image(),
            vpn_config: String::new(),
            exclude_ports: String::new(),
            no_report: false,
            stealth_mode: false,
        }
    }
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            ports: PortConfig::default(),
            timeouts: TimeoutConfig::default(),
            concurrency: ConcurrencyConfig::default(),
            scan: ScanConfig::default(),
            wordlist_subdomains_file: default_wordlist_subdomains(),
            wordlist_directories_file: default_wordlist_directories(),
            wordlist_ctf_files_file: default_wordlist_ctf(),
        }
    }
}

impl Default for PortConfig {
    fn default() -> Self {
        Self {
            default: default_ports_default(),
            ctf: default_ports_ctf(),
            quick: default_ports_quick(),
        }
    }
}

impl Default for TimeoutConfig {
    fn default() -> Self {
        Self {
            connect_ms: default_connect_ms(),
            ctf_connect_ms: default_ctf_connect_ms(),
            http_secs: default_http_secs(),
            dns_secs: default_dns_secs(),
            banner_secs: default_banner_secs(),
        }
    }
}

impl Default for ConcurrencyConfig {
    fn default() -> Self {
        Self {
            port_scan_batch: default_port_scan_batch(),
            port_scan_ctf_batch: default_port_scan_ctf_batch(),
            dns_semaphore: default_dns_semaphore(),
            web_semaphore: default_web_semaphore(),
        }
    }
}

impl PortEntry {
    pub fn expand(&self) -> Vec<u16> {
        match self {
            PortEntry::Single(p) => vec![*p],
            PortEntry::Range(r) => (r.start..=r.end).collect(),
        }
    }
}

fn default_ports_default() -> Vec<PortEntry> {
    vec![
        21, 22, 23, 25, 53, 80, 81, 110, 111, 135, 139, 143, 161, 389, 443, 445, 465, 500, 513,
        554, 587, 593, 636, 873, 990, 993, 995, 1433, 1521, 1723, 2049, 2082, 2083, 2181, 2222,
        2375, 2376, 3000, 3128, 3268, 3269, 3306, 3389, 3478, 3632, 3690, 4000, 4040, 4444, 4500,
        4848, 5000, 5432, 5555, 5601, 5666, 5672, 5800, 5900, 5901, 5984, 5985, 5986, 6000, 6379,
        6443, 6697, 7000, 7001, 7002, 7070, 7777, 8000, 8008, 8443, 8500, 8600, 8649, 8834, 8880,
        8888, 9000, 9001, 9002, 9042, 9050, 9060, 9080, 9090, 9091, 9100, 9200, 9300, 9418, 9443,
        9999, 10000, 10050, 10051, 10443, 11000, 11211, 12345, 13337, 17000, 18100, 18200,
    ].into_iter().map(PortEntry::Single).collect()
}

fn default_ports_ctf() -> Vec<PortEntry> {
    let mut ports: Vec<PortEntry> = Vec::new();
    ports.push(PortEntry::Range(PortRange { start: 1, end: 1024 }));
    for &p in &[1433, 1521, 2049, 2222, 2375, 2376, 2443, 3000, 3128, 3306, 3389, 3478, 3632,
        3690, 4000, 4040, 4444, 4500, 4848, 6379, 6443, 6697, 7000, 7001, 7002, 7070, 7777, 8000,
        8008, 8181, 8222, 8243, 8280, 8300, 8400, 8443, 8500, 8600, 8649, 8834, 8880, 8888, 9200,
        9300, 9418, 9443, 9999, 10000, 10050, 10051, 10443, 11000, 11211, 12345, 13337, 27017,
        27018, 27019, 31337, 32764, 42000, 42001] {
        ports.push(PortEntry::Single(p));
    }
    ports.push(PortEntry::Range(PortRange { start: 5000, end: 6000 }));
    ports.push(PortEntry::Range(PortRange { start: 8080, end: 8090 }));
    ports.push(PortEntry::Range(PortRange { start: 9000, end: 9100 }));
    ports.push(PortEntry::Range(PortRange { start: 16000, end: 16100 }));
    ports.push(PortEntry::Range(PortRange { start: 17000, end: 17001 }));
    ports.push(PortEntry::Range(PortRange { start: 18080, end: 18200 }));
    ports.push(PortEntry::Range(PortRange { start: 32771, end: 32779 }));
    ports.push(PortEntry::Range(PortRange { start: 43000, end: 43010 }));
    ports.push(PortEntry::Range(PortRange { start: 49152, end: 49156 }));
    ports
}

fn default_ports_quick() -> Vec<u16> {
    vec![21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 389, 443, 445, 993, 995, 1433, 1521,
         2049, 3000, 3306, 3389, 5000, 5432, 5900, 5985, 5986, 6379, 8000, 8080, 8443, 8888,
         9090, 27017]
}

fn default_connect_ms() -> u64 { 100 }
fn default_ctf_connect_ms() -> u64 { 80 }
fn default_http_secs() -> u64 { 3 }
fn default_dns_secs() -> u64 { 3 }
fn default_banner_secs() -> u64 { 2 }

fn default_port_scan_batch() -> usize { 10 }
fn default_port_scan_ctf_batch() -> usize { 20 }
fn default_dns_semaphore() -> usize { 10 }
fn default_web_semaphore() -> usize { 15 }

fn default_report_path() -> String { "reports".into() }
fn default_user_agent() -> String {
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36".into()
}
fn default_osint_ua() -> String { "Sentinel OSINT/1.0".into() }
fn default_wordlist_subdomains() -> String { "wordlists/subdomains.txt".into() }
fn default_wordlist_directories() -> String { "wordlists/directories.txt".into() }
fn default_wordlist_ctf() -> String { "wordlists/ctf_files.txt".into() }
fn default_docker_image() -> String { "kalilinux/kali-rolling".into() }

// Note: additional impl blocks exist above for Settings, ScanConfig, PortConfig, etc.
