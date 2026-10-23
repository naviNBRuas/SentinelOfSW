#![allow(dead_code)]

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::process::{Child, Command};
use tokio::sync::Mutex;
use tokio::time::{sleep, Duration};

#[derive(Debug, Clone, PartialEq)]
pub enum VpnType {
    OpenVpn,
    WireGuard,
}

#[derive(Debug, Clone)]
pub struct VpnConfig {
    pub name: String,
    pub path: PathBuf,
    pub vpn_type: VpnType,
}

#[derive(Debug, Clone, PartialEq)]
pub enum VpnStatus {
    Disconnected,
    Connecting,
    Connected { interface: String, ip: String },
    Failed { error: String },
}

pub struct VpnManager {
    pub status: Arc<Mutex<VpnStatus>>,
    pub config_dir: PathBuf,
    process: Arc<Mutex<Option<Child>>>,
    should_stop: Arc<AtomicBool>,
}

impl VpnManager {
    pub fn new() -> Self {
        let config_dir = PathBuf::from("vpn");
        if !config_dir.exists() {
            let _ = std::fs::create_dir_all(&config_dir);
        }
        Self {
            status: Arc::new(Mutex::new(VpnStatus::Disconnected)),
            config_dir,
            process: Arc::new(Mutex::new(None)),
            should_stop: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn list_configs(&self) -> Vec<VpnConfig> {
        let mut configs = Vec::new();
        if !self.config_dir.exists() {
            return configs;
        }
        if let Ok(entries) = std::fs::read_dir(&self.config_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if let Some(ext) = path.extension() {
                    if ext == "ovpn" {
                        let name = path.file_stem().unwrap_or_default().to_string_lossy().into_owned();
                        configs.push(VpnConfig {
                            name,
                            path,
                            vpn_type: VpnType::OpenVpn,
                        });
                    } else if ext == "conf" {
                        let name = path.file_stem().unwrap_or_default().to_string_lossy().into_owned();
                        configs.push(VpnConfig {
                            name,
                            path,
                            vpn_type: VpnType::WireGuard,
                        });
                    }
                }
            }
        }
        configs
    }

    pub fn find_config(&self, name_or_path: &str) -> Option<VpnConfig> {
        let path = Path::new(name_or_path);
        if path.exists() {
            let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
            let name = path.file_stem().unwrap_or_default().to_string_lossy().into_owned();
            return Some(VpnConfig {
                name,
                path: path.to_path_buf(),
                vpn_type: if ext == "ovpn" { VpnType::OpenVpn } else { VpnType::WireGuard },
            });
        }
        self.list_configs().into_iter().find(|c| c.name == name_or_path)
    }

    pub async fn connect(&self, config: &VpnConfig) -> Result<()> {
        {
            let mut status = self.status.lock().await;
            *status = VpnStatus::Connecting;
        }

        match config.vpn_type {
            VpnType::OpenVpn => self.connect_openvpn(config).await?,
            VpnType::WireGuard => self.connect_wireguard(config).await?,
        }

        self.start_connectivity_monitor().await;
        Ok(())
    }

    async fn connect_openvpn(&self, config: &VpnConfig) -> Result<()> {
        let config_path = config.path.to_string_lossy().to_string();

        // Check OpenSSL version for tls-cipher compatibility
        let tls_override = if openvpn_needs_tls_cipher_fix().await {
            Some("--tls-cipher")
        } else {
            None
        };

        let mut cmd_args = vec!["openvpn", "--config", &config_path, "--daemon", "--log", "/tmp/sentinel_vpn.log"];
        if let Some(cipher_flag) = tls_override {
            cmd_args.push(cipher_flag);
            cmd_args.push("PROFILE=SYSTEM");
        }

        let mut child = Command::new("sudo")
            .args(&cmd_args)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .context("Failed to spawn OpenVPN. Is openvpn installed? Try: sudo apt install openvpn")?;

        child.wait().await?;

        sleep(Duration::from_secs(3)).await;
        self.detect_vpn_interface("tun", &config.name).await;

        let mut proc = self.process.lock().await;
        *proc = Some(child);
        Ok(())
    }

    async fn connect_wireguard(&self, config: &VpnConfig) -> Result<()> {
        let config_path = config.path.to_string_lossy().to_string();

        let mut child = Command::new("sudo")
            .args(["wg-quick", "up", &config_path])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("Failed to spawn WireGuard. Is wireguard-tools installed? Try: sudo apt install wireguard-tools")?;

        child.wait().await?;

        sleep(Duration::from_secs(2)).await;
        self.detect_vpn_interface("wg", &config.name).await;

        let mut proc = self.process.lock().await;
        *proc = Some(child);
        Ok(())
    }

    async fn detect_vpn_interface(&self, prefix: &str, _name: &str) {
        let search_pattern = if prefix == "tun" { "tun" } else { prefix };

        for i in 0..15 {
            // Check for VPN interface
            if let Ok(output) = Command::new("ip").args(["addr", "show"]).output().await {
                let stdout = String::from_utf8_lossy(&output.stdout);
                if let Some(ip) = extract_ip_from_output(&stdout, search_pattern) {
                    let iface = find_vpn_interface(&stdout, search_pattern);
                    let mut status = self.status.lock().await;
                    *status = VpnStatus::Connected {
                        interface: iface.unwrap_or_else(|| search_pattern.to_string()),
                        ip,
                    };
                    return;
                }
            }

            // Check OpenVPN log for progress
            if let Ok(log) = tokio::fs::read_to_string("/tmp/sentinel_vpn.log").await {
                if log.contains("Initialization Sequence Completed") {
                    sleep(Duration::from_secs(1)).await;
                    if let Ok(output) = Command::new("ip").args(["addr", "show"]).output().await {
                        let stdout = String::from_utf8_lossy(&output.stdout);
                        if let Some(ip) = extract_ip_from_output(&stdout, search_pattern) {
                            let mut status = self.status.lock().await;
                            *status = VpnStatus::Connected {
                                interface: search_pattern.to_string(),
                                ip,
                            };
                            return;
                        }
                    }
                }
                // TLS errors mean the VPN handshake is failing — bail fast
                if i >= 3 && log.contains("TLS Error") {
                    let mut status = self.status.lock().await;
                    *status = VpnStatus::Failed {
                        error: "VPN TLS handshake failed — check network/firewall".to_string(),
                    };
                    return;
                }
            }

            sleep(Duration::from_secs(2)).await;
        }

        let mut status = self.status.lock().await;
        let error = if let Ok(log) = tokio::fs::read_to_string("/tmp/sentinel_vpn.log").await {
            if log.contains("TLS Error") || log.contains("tls-error") {
                "VPN TLS handshake failed — check network/firewall".to_string()
            } else {
                format!("VPN interface ({}) not detected after connection", prefix)
            }
        } else {
            format!("VPN interface ({}) not detected after connection", prefix)
        };
        *status = VpnStatus::Failed { error };
    }

    fn extract_ip_from_interface(&self, stdout: &str, iface: &str) -> Option<String> {
        extract_ip_from_output(stdout, iface)
    }

    async fn start_connectivity_monitor(&self) {
        let status = Arc::clone(&self.status);
        let should_stop = Arc::clone(&self.should_stop);
        tokio::spawn(async move {
            loop {
                if should_stop.load(Ordering::Relaxed) {
                    break;
                }
                let current = status.lock().await.clone();
                if matches!(current, VpnStatus::Connected { .. })
                    && !check_vpn_connectivity().await {
                    let mut s = status.lock().await;
                    *s = VpnStatus::Failed {
                        error: "VPN connection lost".into(),
                    };
                    break;
                }
                sleep(Duration::from_secs(5)).await;
            }
        });
    }

    pub async fn disconnect(&self) -> Result<()> {
        self.should_stop.store(true, Ordering::Relaxed);

        let current = self.status.lock().await.clone();
        let vpn_type = match &current {
            VpnStatus::Connected { interface, .. } => {
                if interface.starts_with("wg") || interface.starts_with("wg") {
                    VpnType::WireGuard
                } else {
                    VpnType::OpenVpn
                }
            }
            _ => {
                let mut proc = self.process.lock().await;
                if let Some(ref mut child) = *proc {
                    let _ = child.kill().await;
                }
                let mut status = self.status.lock().await;
                *status = VpnStatus::Disconnected;
                return Ok(());
            }
        };

        match vpn_type {
            VpnType::OpenVpn => {
                let _ = Command::new("sudo")
                    .args(["killall", "openvpn"])
                    .stdout(Stdio::null()).stderr(Stdio::null())
                    .spawn();
            }
            VpnType::WireGuard => {
                let mut proc = self.process.lock().await;
                if let Some(ref mut child) = *proc {
                    let _ = child.kill().await;
                }
                drop(proc);
            }
        }

        // Kill remaining processes
        let mut proc = self.process.lock().await;
        if let Some(ref mut child) = *proc {
            let _ = child.kill().await;
        }
        *proc = None;

        let mut status = self.status.lock().await;
        *status = VpnStatus::Disconnected;
        Ok(())
    }

    pub async fn active_gateway(&self) -> Option<String> {
        let status = self.status.lock().await;
        match &*status {
            VpnStatus::Connected { ip, .. } => {
                if let Some(gw) = ip.split('/').next() {
                    let parts: Vec<&str> = gw.split('.').collect();
                    if parts.len() == 4 && parts[3] == "1" {
                        Some(gw.to_string())
                    } else if parts.len() == 4 {
                        let mut gw_parts = parts.clone();
                        gw_parts[3] = "1";
                        Some(gw_parts.join("."))
                    } else {
                        None
                    }
                } else {
                    None
                }
            }
            _ => None,
        }
    }
}

impl Drop for VpnManager {
    fn drop(&mut self) {
        self.should_stop.store(true, Ordering::Relaxed);
    }
}

async fn check_vpn_connectivity() -> bool {
    if let Ok(output) = Command::new("ping")
        .args(["-c", "1", "-W", "2", "10.10.10.1"])
        .output().await
    {
        if output.status.success() {
            return true;
        }
    }
    if let Ok(output) = Command::new("ping")
        .args(["-c", "1", "-W", "2", "10.10.0.1"])
        .output().await
    {
        if output.status.success() {
            return true;
        }
    }
    // Check if tun/wg interfaces exist at all
    if let Ok(output) = Command::new("ip").args(["addr", "show"]).output().await {
        let stdout = String::from_utf8_lossy(&output.stdout);
        if stdout.contains("tun") || stdout.contains("wg") {
            return true;
        }
    }
    false
}

fn extract_ip_from_output(stdout: &str, iface_prefix: &str) -> Option<String> {
    let lines: Vec<&str> = stdout.lines().collect();
    let mut in_interface = false;
    for line in &lines {
        let trimmed = line.trim();
        if trimmed.starts_with(|c: char| c.is_ascii_digit()) && trimmed.contains(&format!("{}:", iface_prefix)) && trimmed.contains('<') {
            in_interface = true;
            continue;
        }
        if in_interface {
            let trimmed = line.trim();
            if trimmed.starts_with("inet ") {
                let parts: Vec<&str> = trimmed.split_whitespace().collect();
                if parts.len() >= 2 {
                    return Some(parts[1].to_string());
                }
            }
            if trimmed.starts_with("inet6 ") || trimmed.is_empty() {
                in_interface = false;
            }
        }
    }
    None
}

fn find_vpn_interface(stdout: &str, iface_prefix: &str) -> Option<String> {
    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with(|c: char| c.is_ascii_digit()) && trimmed.contains(&format!("{}:", iface_prefix)) && trimmed.contains('<') {
            if let Some(name) = trimmed.split(':').nth(1) {
                let name = name.trim();
                if name.starts_with(iface_prefix) {
                    return Some(name.to_string());
                }
            }
        }
    }
    None
}

/// Check if OpenVPN's tls-cipher needs workaround for OpenSSL 3.x compatibility
async fn openvpn_needs_tls_cipher_fix() -> bool {
    if let Ok(output) = Command::new("openvpn").arg("--version").output().await {
        let stdout = String::from_utf8_lossy(&output.stdout);
        // OpenVPN 2.7+ with OpenSSL 3.x has issues with @SECLEVEL=0 cipher syntax
        stdout.contains("OpenVPN 2.7") && stdout.contains("OpenSSL 3.")
    } else {
        false
    }
}
