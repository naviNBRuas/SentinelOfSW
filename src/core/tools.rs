#![allow(dead_code)]

use crate::core::docker::DockerManager;
use tokio::process::Command;

/// Represents an external security tool available for use
#[derive(Debug, Clone)]
pub struct SecurityTool {
    pub name: &'static str,
    pub binary: &'static str,
    pub install_hint: &'static str,
    pub available_via_docker: bool,
    pub available_via_system: bool,
}

impl SecurityTool {
    pub fn all() -> Vec<SecurityTool> {
        vec![
            SecurityTool { name: "Nmap", binary: "nmap", install_hint: "sudo apt install nmap", available_via_docker: true, available_via_system: false },
            SecurityTool { name: "Ffuf", binary: "ffuf", install_hint: "sudo apt install ffuf", available_via_docker: true, available_via_system: false },
            SecurityTool { name: "Gobuster", binary: "gobuster", install_hint: "sudo apt install gobuster", available_via_docker: true, available_via_system: false },
            SecurityTool { name: "Nikto", binary: "nikto", install_hint: "sudo apt install nikto", available_via_docker: true, available_via_system: false },
            SecurityTool { name: "Hydra", binary: "hydra", install_hint: "sudo apt install hydra", available_via_docker: true, available_via_system: false },
            SecurityTool { name: "Enum4linux", binary: "enum4linux-ng", install_hint: "sudo apt install enum4linux-ng", available_via_docker: true, available_via_system: false },
            SecurityTool { name: "Dnsrecon", binary: "dnsrecon", install_hint: "sudo apt install dnsrecon", available_via_docker: true, available_via_system: false },
            SecurityTool { name: "theHarvester", binary: "theHarvester", install_hint: "sudo apt install theharvester", available_via_docker: true, available_via_system: false },
            SecurityTool { name: "Searchsploit", binary: "searchsploit", install_hint: "sudo apt install exploitdb", available_via_docker: true, available_via_system: false },
            SecurityTool { name: "Sslscan", binary: "sslscan", install_hint: "sudo apt install sslscan", available_via_docker: true, available_via_system: false },
            SecurityTool { name: "Smbclient", binary: "smbclient", install_hint: "sudo apt install smbclient", available_via_docker: true, available_via_system: false },
            SecurityTool { name: "Smbmap", binary: "smbmap", install_hint: "sudo apt install smbmap", available_via_docker: true, available_via_system: false },
            SecurityTool { name: "Ldapsearch", binary: "ldapsearch", install_hint: "sudo apt install ldap-utils", available_via_docker: true, available_via_system: false },
            SecurityTool { name: "Rpcclient", binary: "rpcclient", install_hint: "sudo apt install rpcclient", available_via_docker: true, available_via_system: false },
            SecurityTool { name: "Whois", binary: "whois", install_hint: "sudo apt install whois", available_via_docker: true, available_via_system: false },
            SecurityTool { name: "Curl", binary: "curl", install_hint: "sudo apt install curl", available_via_docker: true, available_via_system: false },
        ]
    }

    pub fn find(name: &str) -> Option<SecurityTool> {
        Self::all().into_iter().find(|t| t.name.eq_ignore_ascii_case(name) || t.binary.eq_ignore_ascii_case(name))
    }
}

/// Results from running an external tool
#[derive(Debug, Clone)]
pub struct ToolResult {
    pub tool: String,
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
    pub timed_out: bool,
}

/// Execute a security tool, optionally via Docker
pub async fn run_tool(
    tool_name: &str,
    args: &[&str],
    docker: Option<&DockerManager>,
    timeout_secs: u64,
) -> ToolResult {
    if let Some(dm) = docker {
        let result = dm.exec_with_timeout(tool_name, args, timeout_secs).await;
        match result {
            Ok((stdout, stderr)) => ToolResult {
                tool: tool_name.to_string(),
                stdout,
                stderr,
                exit_code: 0,
                timed_out: false,
            },
            Err(e) => ToolResult {
                tool: tool_name.to_string(),
                stdout: String::new(),
                stderr: format!("{}", e),
                exit_code: -1,
                timed_out: e.to_string().contains("timeout"),
            },
        }
    } else {
        // Try system binary
        let binary = SecurityTool::find(tool_name)
            .map(|t| t.binary.to_string())
            .unwrap_or_else(|| tool_name.to_string());

        let output = Command::new(&binary)
            .args(args)
            .output()
            .await;

        match output {
            Ok(o) => {
                let stdout = String::from_utf8_lossy(&o.stdout).to_string();
                let stderr = String::from_utf8_lossy(&o.stderr).to_string();
                ToolResult {
                    tool: tool_name.to_string(),
                    stdout,
                    stderr,
                    exit_code: o.status.code().unwrap_or(-1),
                    timed_out: false,
                }
            }
            Err(e) => ToolResult {
                tool: tool_name.to_string(),
                stdout: String::new(),
                stderr: format!("Failed to execute {}: {}", binary, e),
                exit_code: -1,
                timed_out: false,
            },
        }
    }
}

/// Convenient wrapper: run Nmap scan
pub async fn run_nmap(target: &str, ports: &[u16], args: &[&str], docker: Option<&DockerManager>, timeout: u64) -> ToolResult {
    let mut all_args: Vec<String> = Vec::new();
    all_args.push("-oG".into());
    all_args.push("-".into()); // Grepable output to stdout
    all_args.extend(args.iter().map(|a| a.to_string()));

    if !ports.is_empty() {
        let port_str = ports.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(",");
        all_args.push("-p".into());
        all_args.push(port_str);
    }

    all_args.push(target.to_string());

    let str_args: Vec<&str> = all_args.iter().map(|s| s.as_str()).collect();
    run_tool("nmap", &str_args, docker, timeout).await
}

/// Wrapper: run Nikto web scan
pub async fn run_nikto(target: &str, port: u16, docker: Option<&DockerManager>, timeout: u64) -> ToolResult {
    let url = format!("http://{}:{}", target, port);
    let args = vec!["-h", &url, "-nointeractive", "-Tuning", "123456789"];
    run_tool("nikto", &args, docker, timeout).await
}

/// Wrapper: run Ffuf directory scan
pub async fn run_ffuf(target: &str, port: u16, wordlist: &str, docker: Option<&DockerManager>, timeout: u64) -> ToolResult {
    let url = format!("http://{}:{}/FUZZ", target, port);
    let args = vec!["-u", &url, "-w", wordlist, "-fc", "404", "-t", "50", "-timeout", "3"];
    run_tool("ffuf", &args, docker, timeout).await
}

/// Wrapper: run Gobuster directory scan
pub async fn run_gobuster(target: &str, port: u16, wordlist: &str, docker: Option<&DockerManager>, timeout: u64) -> ToolResult {
    let url = format!("http://{}:{}", target, port);
    let args = vec!["dir", "-u", &url, "-w", wordlist, "-x", "php,txt,html,asp,aspx,jsp,do,js", "-t", "30", "-s", "200,204,301,302,307,401,403"];
    run_tool("gobuster", &args, docker, timeout).await
}

/// Wrapper: run Hydra for credential brute-forcing
pub async fn run_hydra(target: &str, service: &str, port: u16, user: &str, passlist: &str, docker: Option<&DockerManager>, timeout: u64) -> ToolResult {
    let port_str = port.to_string();
    let url = format!("{}://{}", service, target);
    let args = vec!["-l", user, "-P", passlist, "-s", &port_str, "-t", "4", "-o", "/dev/stdout", &url];
    run_tool("hydra", &args, docker, timeout).await
}

/// Wrapper: run Searchsploit
pub async fn run_searchsploit(query: &str, docker: Option<&DockerManager>, timeout: u64) -> ToolResult {
    let args = vec![query];
    run_tool("searchsploit", &args, docker, timeout).await
}

/// Wrapper: run Enum4linux
pub async fn run_enum4linux(target: &str, docker: Option<&DockerManager>, timeout: u64) -> ToolResult {
    let args = vec!["-a", target];
    run_tool("enum4linux-ng", &args, docker, timeout).await
}

/// Wrapper: run Smbmap
pub async fn run_smbmap(target: &str, docker: Option<&DockerManager>, timeout: u64) -> ToolResult {
    let args = vec!["-H", target];
    run_tool("smbmap", &args, docker, timeout).await
}

/// Wrapper: run Sslscan for TLS certificate analysis
pub async fn run_sslscan(target: &str, port: u16, docker: Option<&DockerManager>, timeout: u64) -> ToolResult {
    let hostport = format!("{}:{}", target, port);
    let args = vec!["--no-colour", hostport.as_str()];
    run_tool("sslscan", &args, docker, timeout).await
}

/// Wrapper: run Ldapsearch
pub async fn run_ldapsearch(target: &str, base_dn: &str, docker: Option<&DockerManager>, timeout: u64) -> ToolResult {
    let ldap_url = format!("ldap://{}", target);
    let args = vec!["-x", "-H", ldap_url.as_str(), "-b", base_dn];
    run_tool("ldapsearch", &args, docker, timeout).await
}

/// Check if a system binary is available
pub fn is_tool_available(binary: &str) -> bool {
    which::which(binary).is_ok()
}
