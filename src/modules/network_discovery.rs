use crate::core::findings::{Finding, Severity};
use crate::core::workflow::WorkflowMode;
use crate::modules::Module;
use async_trait::async_trait;
use tokio::process::Command;
use tokio::sync::mpsc::Sender;
use std::time::Duration;

pub struct NetworkDiscovery;

#[async_trait]
impl Module for NetworkDiscovery {
    fn name(&self) -> &str {
        "Network Discovery"
    }

    async fn execute_with_ports(&self, target: &str, open_ports: &[u16], _mode: &WorkflowMode, tx: Sender<String>) -> Result<Vec<Finding>, anyhow::Error> {
        let _ = tx.send("[NetworkDiscovery] Starting network discovery...".into()).await;
        let mut findings = Vec::new();

        let _ = tx.send(format!("[NetworkDiscovery] Pinging {}...", target)).await;
        match Self::ping(target).await {
            Ok(alive) => {
                if alive {
                    findings.push(
                        Finding::new(target, "network_discovery", "Host is Alive",
                            "Target responded to ICMP echo request (ping). Host is reachable on the network.",
                            Severity::Info,
                        ).with_confidence(0.95)
                        .with_evidence(vec!["ICMP echo reply received".into()]),
                    );
                    let _ = tx.send(format!("[NetworkDiscovery] {} is alive", target)).await;
                } else {
                    findings.push(
                        Finding::new(target, "network_discovery", "Host did not respond to Ping",
                            "Target did not respond to ICMP echo request. Host may be down, firewalled, or blocking ICMP.",
                            Severity::Info,
                        ).with_confidence(0.6)
                        .with_evidence(vec!["No ICMP echo reply received within timeout".into()]),
                    );
                    let _ = tx.send(format!("[NetworkDiscovery] {} did not respond to ping", target)).await;
                }
            }
            Err(e) => {
                let _ = tx.send(format!("[NetworkDiscovery] Ping failed: {}", e)).await;
                findings.push(
                    Finding::new(target, "network_discovery", "Ping Sweep Failed",
                        &format!("Could not ping target: {}", e),
                        Severity::Info,
                    ).with_confidence(0.5),
                );
            }
        }

        let _ = tx.send(format!("[NetworkDiscovery] Running traceroute to {}...", target)).await;
        match Self::traceroute(target).await {
            Ok(hops) => {
                if hops > 0 {
                    findings.push(
                        Finding::new(target, "network_discovery", &format!("Traceroute: {} hops to target", hops),
                            &format!("Network path to target requires {} hops. This reveals network topology and intermediate gateways.", hops),
                            Severity::Info,
                        ).with_confidence(0.9)
                        .with_evidence(vec![format!("{} network hops discovered", hops)]),
                    );
                    let _ = tx.send(format!("[NetworkDiscovery] {} hops to target", hops)).await;
                }
            }
            Err(e) => {
                let _ = tx.send(format!("[NetworkDiscovery] Traceroute failed: {}", e)).await;
            }
        }

        if !open_ports.is_empty() {
            findings.push(
                Finding::new(target, "network_discovery", "Network Proximity Assessment",
                    &format!("{} open service(s) detected on target. Services accessible at open ports confirm host reachability at the application layer.", open_ports.len()),
                    Severity::Info,
                ).with_confidence(0.8)
                .with_evidence(vec![format!("{} open ports on target", open_ports.len())]),
            );
        }

        if findings.is_empty() {
            findings.push(
                Finding::new(target, "network_discovery", "Network Discovery Complete",
                    "Network discovery finished. No significant findings.",
                    Severity::Info,
                ).with_confidence(1.0),
            );
        }

        let _ = tx.send(format!("[NetworkDiscovery] Complete. {} findings.", findings.len())).await;
        Ok(findings)
    }
}

impl NetworkDiscovery {
    async fn ping(target: &str) -> Result<bool, anyhow::Error> {
        let result = tokio::time::timeout(Duration::from_secs(5), async {
            Command::new("ping")
                .args(["-c", "1", "-W", "2", target])
                .output()
                .await
        }).await;

        match result {
            Ok(Ok(output)) => Ok(output.status.success()),
            Ok(Err(e)) => Err(anyhow::anyhow!("ping command failed: {}", e)),
            Err(_) => Err(anyhow::anyhow!("ping timed out after 5 seconds")),
        }
    }

    async fn traceroute(target: &str) -> Result<usize, anyhow::Error> {
        let result = tokio::time::timeout(Duration::from_secs(30), async {
            Command::new("traceroute")
                .args(["-n", "-m", "15", target])
                .output()
                .await
        }).await;

        let output = match result {
            Ok(Ok(o)) => o,
            Ok(Err(e)) => return Err(anyhow::anyhow!("traceroute command failed: {}", e)),
            Err(_) => return Err(anyhow::anyhow!("traceroute timed out after 30 seconds")),
        };

        if !output.status.success() {
            return Ok(0);
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let hop_count = stdout.lines()
            .filter(|line| {
                let t = line.trim();
                t.starts_with(|c: char| c.is_ascii_digit()) || t.starts_with(" *")
            })
            .count();
        Ok(hop_count)
    }
}
