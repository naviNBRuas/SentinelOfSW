use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum WorkflowMode {
    Beginner,
    Professional,
    Ctf,
    Quick,
    Stealth,
    ReconOnly,
    Full,
}

impl WorkflowMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Ctf => "ctf",
            Self::Professional => "professional",
            Self::Beginner => "beginner",
            Self::Quick => "quick",
            Self::Stealth => "stealth",
            Self::ReconOnly => "recon-only",
            Self::Full => "full",
        }
    }

    pub fn all() -> &'static [WorkflowMode] {
        &[
            Self::Beginner,
            Self::Professional,
            Self::Ctf,
            Self::Quick,
            Self::Stealth,
            Self::ReconOnly,
            Self::Full,
        ]
    }

    pub fn description(&self) -> &'static str {
        match self {
            Self::Beginner => "Verbose, educational, all modules",
            Self::Professional => "Concise output, minimal explanations",
            Self::Ctf => "Aggressive: ~6500 ports, flag hunting, OSINT",
            Self::Quick => "Fast: 31 common ports only",
            Self::Stealth => "Evasion: random jitter, no banners, low concurrency",
            Self::ReconOnly => "Recon only: DNS + port scan, no exploitation",
            Self::Full => "Maximum: all modules, aggressive concurrency",
        }
    }
}

impl std::fmt::Display for WorkflowMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowStep {
    pub id: usize,
    pub module: String,
    pub description: String,
    pub technique: String,
    pub depends_on: Vec<usize>,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowPlan {
    pub name: String,
    pub description: String,
    pub steps: Vec<WorkflowStep>,
    pub estimated_time: String,
}

pub struct WorkflowEngine;

impl WorkflowEngine {
    pub fn suggest(
        target: &str,
        open_ports: &[u16],
        mode: &WorkflowMode,
    ) -> WorkflowPlan {
        let mut steps = Vec::new();
        let mut id = 1;
        let is_ctf = matches!(mode, WorkflowMode::Ctf);
        let is_stealth = matches!(mode, WorkflowMode::Stealth);
        let is_recon = matches!(mode, WorkflowMode::ReconOnly);
        let is_full = matches!(mode, WorkflowMode::Full);
        let has_http = open_ports.iter().any(|p| [80, 443, 8080, 8443, 8000, 3000, 5000, 8888, 9090].contains(p));
        let has_smb = open_ports.contains(&445);

        // Phase 1: Recon (not in recon-only if we already know nothing)
        steps.push(WorkflowStep {
            id,
            module: "recon".into(),
            description: "DNS Enumeration & Subdomain Discovery".into(),
            technique: "DNS_QUERY".into(),
            depends_on: vec![],
            confidence: 0.9,
        });
        id += 1;

        // Phase 2: Port scanning
        steps.push(WorkflowStep {
            id,
            module: "port_scan".into(),
            description: if is_stealth { "TCP Port Scan (stealth: jitter, low concurrency)".into() }
                        else { "TCP Port Scan".into() },
            technique: "TCP_CONNECT".into(),
            depends_on: vec![id - 1],
            confidence: 0.95,
        });
        id += 1;

        // Phase 3: Network discovery (always runs after port scan)
        steps.push(WorkflowStep {
            id,
            module: "network_discovery".into(),
            description: "Network Discovery (ping sweep, traceroute, topology)".into(),
            technique: "NETWORK_DISCOVERY".into(),
            depends_on: vec![id - 1],
            confidence: 0.9,
        });
        id += 1;

        // Phase 4: Service-specific enumeration (skip for recon-only after port scan)
        if !is_recon {
            if has_http {
                steps.push(WorkflowStep {
                    id,
                    module: "web".into(),
                    description: "Web Enumeration (directories, tech detection, flags)".into(),
                    technique: "HTTP_ENUM".into(),
                    depends_on: vec![id - 1],
                    confidence: 0.9,
                });
                id += 1;

                if is_ctf || is_full {
                    steps.push(WorkflowStep {
                        id,
                        module: "exploit".into(),
                        description: "Exploitation Strategy & Vulnerability Mapping".into(),
                        technique: "EXPLOIT_HUNT".into(),
                        depends_on: vec![id - 1],
                        confidence: 0.8,
                    });
                    id += 1;
                }
            }

            if has_smb {
                steps.push(WorkflowStep {
                    id,
                    module: "smb".into(),
                    description: "SMB Enumeration (Negotiation, Signing, Shares)".into(),
                    technique: "SMB_ENUM".into(),
                    depends_on: vec![id - 1],
                    confidence: 0.85,
                });
                id += 1;
            }

            if !open_ports.is_empty() {
                steps.push(WorkflowStep {
                    id,
                    module: "creds".into(),
                    description: "Default Credential Testing on Common Services".into(),
                    technique: "CRED_CHECK".into(),
                    depends_on: vec![id - 1],
                    confidence: 0.7,
                });
                id += 1;
            }

            if (is_ctf || is_full) && !open_ports.is_empty() {
                steps.push(WorkflowStep {
                    id,
                    module: "priv_esc".into(),
                    description: "Privilege Escalation Strategy & Enumeration".into(),
                    technique: "PRIVESC".into(),
                    depends_on: vec![id - 1],
                    confidence: 0.8,
                });
                id += 1;
            }

            if is_ctf || is_full {
                steps.push(WorkflowStep {
                    id,
                    module: "osint".into(),
                    description: "Passive OSINT (crt.sh, DNS records, WHOIS)".into(),
                    technique: "OSINT".into(),
                    depends_on: vec![id - 1],
                    confidence: 0.7,
                });
                id += 1;
            }
        }

        // Attack Path Analysis (skip for recon-only)
        if !is_recon {
            steps.push(WorkflowStep {
                id,
                module: "attack_path".into(),
                description: "Attack Path Analysis & Prioritization".into(),
                technique: "GRAPH_ANALYSIS".into(),
                depends_on: (1..id).collect(),
                confidence: 0.6,
            });
        }

        let estimated = match mode {
            WorkflowMode::Ctf => "~10 minutes",
            WorkflowMode::Beginner => "~15 minutes",
            WorkflowMode::Professional => "~8 minutes",
            WorkflowMode::Quick => "~3 minutes",
            WorkflowMode::Stealth => "~25 minutes",
            WorkflowMode::ReconOnly => "~5 minutes",
            WorkflowMode::Full => "~20 minutes",
        };

        WorkflowPlan {
            name: format!("Target Assessment: {}", target),
            description: format!(
                "Automated workflow for {} ({} services detected)",
                target,
                open_ports.len()
            ),
            steps,
            estimated_time: estimated.into(),
        }
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_workflow_mode_display() {
        assert_eq!(WorkflowMode::Beginner.as_str(), "beginner");
        assert_eq!(WorkflowMode::Professional.as_str(), "professional");
        assert_eq!(WorkflowMode::Ctf.as_str(), "ctf");
        assert_eq!(WorkflowMode::Quick.as_str(), "quick");
    }

    #[test]
    fn test_workflow_mode_display_trait() {
        assert_eq!(format!("{}", WorkflowMode::Beginner), "beginner");
        assert_eq!(format!("{}", WorkflowMode::Ctf), "ctf");
        assert_eq!(format!("{}", WorkflowMode::Quick), "quick");
    }

    #[test]
    fn test_plan_basic_no_ports() {
        let plan = WorkflowEngine::suggest("10.10.10.10", &[], &WorkflowMode::Beginner);
        assert!(plan.name.contains("10.10.10.10"));
        assert!(plan.steps.len() >= 2); // recon + port_scan at minimum
        assert_eq!(plan.steps[0].module, "recon");
        assert_eq!(plan.steps[1].module, "port_scan");
    }

    #[test]
    fn test_plan_with_http_triggers_web() {
        let plan = WorkflowEngine::suggest("test.com", &[80, 443], &WorkflowMode::Professional);
        let modules: Vec<&str> = plan.steps.iter().map(|s| s.module.as_str()).collect();
        assert!(modules.contains(&"web"));
    }

    #[test]
    fn test_plan_with_smb_triggers_smb() {
        let plan = WorkflowEngine::suggest("target.local", &[445], &WorkflowMode::Beginner);
        let modules: Vec<&str> = plan.steps.iter().map(|s| s.module.as_str()).collect();
        assert!(modules.contains(&"smb"));
    }

    #[test]
    fn test_plan_ctf_mode_includes_extra() {
        let plan = WorkflowEngine::suggest("ctf.box", &[80, 22], &WorkflowMode::Ctf);
        let modules: Vec<&str> = plan.steps.iter().map(|s| s.module.as_str()).collect();
        assert!(modules.contains(&"web"));
        assert!(modules.contains(&"exploit"));
        assert!(modules.contains(&"priv_esc"));
        assert!(modules.contains(&"osint"));
    }

    #[test]
    fn test_plan_quick_mode_basic() {
        let plan = WorkflowEngine::suggest("10.0.0.1", &[], &WorkflowMode::Quick);
        assert_eq!(plan.estimated_time, "~3 minutes");
        assert!(plan.steps.iter().any(|s| s.module == "recon"));
    }

    #[test]
    fn test_plan_no_http_no_service_steps() {
        let plan = WorkflowEngine::suggest("10.0.0.1", &[123, 161], &WorkflowMode::Beginner);
        let modules: Vec<&str> = plan.steps.iter().map(|s| s.module.as_str()).collect();
        assert!(!modules.contains(&"web"));
        assert!(!modules.contains(&"smb"));
    }

    #[test]
    fn test_plan_dependency_chain() {
        let plan = WorkflowEngine::suggest("test.com", &[80, 445], &WorkflowMode::Beginner);
        for step in &plan.steps {
            if step.module == "port_scan" {
                assert!(step.depends_on.contains(&(step.id - 1)));
            }
        }
        // attack_path depends on all previous
        let attack_path_step = plan.steps.iter().find(|s| s.module == "attack_path").unwrap();
        assert_eq!(attack_path_step.depends_on.len(), plan.steps.len() - 1);
        for i in 1..plan.steps.len() {
            assert!(attack_path_step.depends_on.contains(&i));
        }
    }

    #[test]
    fn test_workflow_step_confidence() {
        let plan = WorkflowEngine::suggest("x.com", &[80], &WorkflowMode::Professional);
        assert!(plan.steps.iter().all(|s| s.confidence > 0.0));
    }

    #[test]
    fn test_plan_estimated_time_by_mode() {
        let beginner = WorkflowEngine::suggest("x", &[], &WorkflowMode::Beginner);
        let quick = WorkflowEngine::suggest("x", &[], &WorkflowMode::Quick);
        assert_eq!(beginner.estimated_time, "~15 minutes");
        assert_eq!(quick.estimated_time, "~3 minutes");
    }

    #[test]
    fn test_plan_with_no_open_ports_no_creds() {
        let plan = WorkflowEngine::suggest("10.0.0.1", &[], &WorkflowMode::Beginner);
        let modules: Vec<&str> = plan.steps.iter().map(|s| s.module.as_str()).collect();
        // creds only runs when open_ports is non-empty
        assert!(!modules.contains(&"creds"));
    }

    #[test]
    fn test_plan_with_open_ports_includes_creds() {
        let plan = WorkflowEngine::suggest("10.0.0.1", &[22], &WorkflowMode::Beginner);
        let modules: Vec<&str> = plan.steps.iter().map(|s| s.module.as_str()).collect();
        assert!(modules.contains(&"creds"));
    }
}
