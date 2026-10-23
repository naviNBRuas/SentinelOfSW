#![allow(dead_code)]

use anyhow::{Context, Result};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use tokio::process::Command;
use tokio::sync::Mutex;


pub static DOCKER_MANAGER: OnceLock<Option<Arc<DockerManager>>> = OnceLock::new();

#[derive(Debug, Clone, PartialEq)]
pub enum DockerStatus {
    Unavailable,
    Pulling,
    Ready { container_id: String, image: String },
    Failed { error: String },
}

pub struct DockerManager {
    pub status: Arc<Mutex<DockerStatus>>,
    pub image: String,
    container_name: String,
    should_stop: Arc<AtomicBool>,
}

impl DockerManager {
    pub fn new(image: Option<&str>) -> Self {
        let image = image.unwrap_or("kalilinux/kali-rolling").to_string();
        let container_name = format!("sentinel-env-{}", std::process::id());
        Self {
            status: Arc::new(Mutex::new(DockerStatus::Unavailable)),
            image,
            container_name,
            should_stop: Arc::new(AtomicBool::new(false)),
        }
    }

    pub async fn is_available() -> bool {
        if let Ok(output) = Command::new("docker").arg("info").output().await {
            return output.status.success();
        }
        false
    }

    pub async fn initialize(&self, send: impl Fn(&str)) -> Result<()> {
        if !Self::is_available().await {
            let mut status = self.status.lock().await;
            *status = DockerStatus::Failed {
                error: "Docker is not available or not running".into(),
            };
            return Err(anyhow::anyhow!("Docker is not available"));
        }

        send("[Docker] Docker is available. Preparing container...");

        // Pull image if not present
        if !self.image_exists().await {
            let mut status = self.status.lock().await;
            *status = DockerStatus::Pulling;
            drop(status);

            send(&format!("[Docker] Pulling image: {} (this may take a while)...", self.image));

            let pull_status = Command::new("docker")
                .args(["pull", &self.image])
                .status()
                .await
                .context("Failed to pull Docker image")?;

            if !pull_status.success() {
                let mut status = self.status.lock().await;
                *status = DockerStatus::Failed {
                    error: format!("Failed to pull image: {}", self.image),
                };
                return Err(anyhow::anyhow!("Failed to pull Docker image"));
            }

            send("[Docker] Image pulled successfully.");
        }

        // Remove any stale container with same name
        let _ = Command::new("docker")
            .args(["rm", "-f", &self.container_name])
            .output().await;

        // Start container with host networking and privileged mode
        send("[Docker] Starting container...");

        let output = Command::new("docker")
            .args([
                "run", "-d",
                "--name", &self.container_name,
                "--network", "host",
                "--privileged",
                "--pid=host",
                "-v", "/:/mnt/host:ro",
                "-v", "/var/run/docker.sock:/var/run/docker.sock",
                &self.image,
                "sleep", "infinity",
            ])
            .output()
            .await
            .context("Failed to start Docker container")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let mut status = self.status.lock().await;
            *status = DockerStatus::Failed {
                error: format!("Failed to start container: {}", stderr),
            };
            return Err(anyhow::anyhow!("Failed to start container: {}", stderr));
        }

        let container_id = String::from_utf8_lossy(&output.stdout).trim().to_string();
        send(&format!("[Docker] Container started: {}", &container_id[..12.min(container_id.len())]));

        // Install essential tools inside container
        send("[Docker] Installing pentesting tools...");
        self.install_tools(&send).await;

        let mut status = self.status.lock().await;
        *status = DockerStatus::Ready {
            container_id: container_id.clone(),
            image: self.image.clone(),
        };
        drop(status);

        send("[Docker] Environment ready — all tools installed.");
        Ok(())
    }

    async fn image_exists(&self) -> bool {
        let output = Command::new("docker")
            .args(["images", "-q", &self.image])
            .output().await;
        match output {
            Ok(o) => !String::from_utf8_lossy(&o.stdout).trim().is_empty(),
            Err(_) => false,
        }
    }

    async fn install_tools(&self, send: &impl Fn(&str)) {
        // Fix apt sources to use archive.kali.org which is more reliable
        let setup = r#"
rm -f /etc/apt/sources.list /etc/apt/sources.list.d/kali.sources 2>/dev/null
mkdir -p /etc/apt
cat > /etc/apt/sources.list << 'EOF'
deb http://http.kali.org/kali kali-rolling main non-free contrib
deb-src http://http.kali.org/kali kali-rolling main non-free contrib
EOF
apt-get update -qq 2>&1 | tail -3
"#;

        send("[Docker] Configuring Kali repositories...");
        let update_out = Command::new("docker")
            .args(["exec", &self.container_name, "bash", "-c", setup])
            .output().await;
        let update_ok = update_out.as_ref().map(|o| o.status.success()).unwrap_or(false);

        if !update_ok {
            send("[Docker] Kali repos unreachable — tools cannot be installed.");
            send("[Docker] Continuing with built-in scanners as fallback.");
            send("[Docker] Full tool support requires internet/VPN access.");
            return;
        }

        send("[Docker] Installing pentesting tools (this may take 2-3 minutes)...");

        // Groups of packages — each group tries to install, failing gracefully
        let tool_groups = vec![
            "nmap ffuf gobuster nikto hydra exploitdb dirbuster sshpass",
            "enum4linux-ng smbclient smbmap ldap-utils dnsutils wordlist",
            "dnsrecon theharvester curl wget sslscan whois netcat-openbsd",
        ];
        for group in &tool_groups {
            let cmd = format!(
                "DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends {} 2>&1 | tail -3",
                group
            );
            let result = Command::new("docker")
                .args(["exec", &self.container_name, "bash", "-c", &cmd])
                .output().await;
            if let Ok(output) = result {
                let out = String::from_utf8_lossy(&output.stdout);
                let tail: Vec<&str> = out.lines().rev().take(2).collect::<Vec<_>>().into_iter().rev().collect();
                for line in tail {
                    let t = line.trim();
                    if !t.is_empty() {
                        send(t);
                    }
                }
            }
        }

        // Verify key tools
        let verify = Command::new("docker")
            .args(["exec", &self.container_name, "bash", "-c",
                "for t in nmap ffuf gobuster nikto hydra enum4linux-ng dnsrecon searchsploit smbclient smbmap sslscan whois; do command -v \"$t\" >/dev/null 2>&1 && echo \"$t: ok\" || echo \"$t: MISSING\"; done"])
            .output().await;
        if let Ok(vout) = verify {
            let installed = String::from_utf8_lossy(&vout.stdout);
            let ok_count = installed.lines().filter(|l| l.ends_with(": ok")).count();
            let missing: Vec<&str> = installed.lines().filter(|l| l.ends_with(": MISSING")).collect();
            if ok_count > 0 {
                send(&format!("[Docker] {}/11 core tools installed.", ok_count));
            }
            if !missing.is_empty() {
                let names: Vec<&str> = missing.iter().map(|l| l.split(':').next().unwrap_or("?")).collect();
                if ok_count == 0 {
                    send("[Docker] Kali repos unreachable — tools not installed.");
                    send("[Docker] Sentinel will use built-in scanners as fallback.");
                    send("[Docker] For full Docker support, ensure internet/VPN access.");
                } else {
                    send(&format!("[Docker] Partial install. Missing: {}", names.join(", ")));
                }
            }
        }
    }

    pub async fn exec(&self, tool: &str, args: &[&str]) -> Result<(String, String)> {
        let container = {
            let status = self.status.lock().await;
            match &*status {
                DockerStatus::Ready { container_id, .. } => container_id.clone(),
                _ => return Err(anyhow::anyhow!("Docker container not ready")),
            }
        };

        let mut cmd_args = vec!["exec", &container, "bash", "-c"];
        let full_cmd = format!("{} {} 2>&1", tool, args.join(" "));
        cmd_args.push(&full_cmd);

        let output = Command::new("docker")
            .args(&cmd_args)
            .output()
            .await
            .context(format!("Failed to execute {} in Docker container", tool))?;

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();

        Ok((stdout, stderr))
    }

    pub async fn exec_with_timeout(&self, tool: &str, args: &[&str], timeout_secs: u64) -> Result<(String, String)> {
        let container = {
            let status = self.status.lock().await;
            match &*status {
                DockerStatus::Ready { container_id, .. } => container_id.clone(),
                _ => return Err(anyhow::anyhow!("Docker container not ready")),
            }
        };

        let full_cmd = format!("timeout {} {} {} 2>&1", timeout_secs, tool, args.join(" "));
        let output = Command::new("docker")
            .args(["exec", &container, "bash", "-c", &full_cmd])
            .output()
            .await
            .context(format!("Failed to execute {} in Docker container", tool))?;

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();

        Ok((stdout, stderr))
    }

    pub async fn cleanup(&self) -> Result<()> {
        self.should_stop.store(true, Ordering::Relaxed);
        let _ = Command::new("docker")
            .args(["rm", "-f", &self.container_name])
            .output().await;
        let mut status = self.status.lock().await;
        *status = DockerStatus::Unavailable;
        Ok(())
    }

    pub fn builder() -> DockerBuilder {
        DockerBuilder::new()
    }
}

impl Drop for DockerManager {
    fn drop(&mut self) {
        if !self.should_stop.load(Ordering::Relaxed) {
            self.should_stop.store(true, Ordering::Relaxed);
            let name = self.container_name.clone();
            tokio::spawn(async move {
                let _ = Command::new("docker").args(["rm", "-f", &name]).output().await;
            });
        }
    }
}

pub struct DockerBuilder {
    image: Option<String>,
}

pub fn set_docker_global(mgr: Option<Arc<DockerManager>>) {
    let _ = DOCKER_MANAGER.set(mgr);
}

pub fn global_docker() -> Option<&'static Arc<DockerManager>> {
    DOCKER_MANAGER.get().and_then(|o| o.as_ref())
}

impl DockerBuilder {
    pub fn new() -> Self {
        Self { image: None }
    }

    pub fn image(mut self, image: &str) -> Self {
        self.image = Some(image.to_string());
        self
    }

    pub async fn build(self) -> Result<DockerManager> {
        let mgr = DockerManager::new(self.image.as_deref());
        // Just validate docker exists
        if !DockerManager::is_available().await {
            return Err(anyhow::anyhow!("Docker is not available"));
        }
        Ok(mgr)
    }
}
