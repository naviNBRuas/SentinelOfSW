use crate::core::correlation::CorrelationEngine;
use crate::core::findings::{AttackPath, Finding, FindingStore, Severity};
use crate::core::workflow::{WorkflowEngine, WorkflowMode, WorkflowPlan};
use petgraph::graph::DiGraph;

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum TaskStatus {
    Pending,
    Running,
    Completed,
    Failed,
}

pub struct Task {
    pub name: String,
    pub status: TaskStatus,
}

pub struct WorkflowOrchestrator {
    pub graph: DiGraph<Task, ()>,
    pub findings: FindingStore,
    pub plan: Option<WorkflowPlan>,
    pub mode: WorkflowMode,
    pub target: String,
    pub open_ports: Vec<u16>,
}

impl WorkflowOrchestrator {
    pub fn new(target: &str, mode: WorkflowMode) -> Self {
        Self {
            graph: DiGraph::new(),
            findings: FindingStore::new(),
            plan: None,
            mode,
            target: target.to_string(),
            open_ports: Vec::new(),
        }
    }

    pub fn add_task(&mut self, name: &str) -> usize {
        self.graph.add_node(Task {
            name: name.to_string(),
            status: TaskStatus::Pending,
        }).index()
    }

    pub fn set_open_ports(&mut self, ports: Vec<u16>) {
        self.open_ports = ports;
    }

    pub fn generate_plan(&mut self) -> &WorkflowPlan {
        let plan = WorkflowEngine::suggest(&self.target, &self.open_ports, &self.mode);
        self.plan = Some(plan);
        self.plan.as_ref().unwrap()
    }

    pub fn add_finding(&mut self, finding: Finding) {
        self.findings.add(finding);
    }

    pub fn generate_attack_paths(&self) -> Vec<AttackPath> {
        let mut paths = Vec::new();
        let has_web = self.open_ports.iter().any(|p| [80, 443, 8080, 8443, 8000, 3000, 5000, 8888, 9090].contains(p));
        let has_smb = self.open_ports.contains(&445);
        let has_ssh = self.open_ports.contains(&22);
        let has_docker_api = self.open_ports.contains(&2375) || self.open_ports.contains(&2376);
        let has_k8s = self.open_ports.contains(&6443) || self.open_ports.contains(&10250);
        let has_db = self.open_ports.iter().any(|p| [3306, 5432, 1433, 27017].contains(p));
        let has_redis = self.open_ports.contains(&6379);
        let has_rdp = self.open_ports.contains(&3389);
        let has_winrm = self.open_ports.contains(&5985) || self.open_ports.contains(&5986);
        let has_ftp = self.open_ports.contains(&21);
        let has_nfs = self.open_ports.contains(&2049);

        let found_creds = self.findings.by_module("creds");
        let has_default_creds = found_creds.iter().any(|f| f.severity == Severity::Critical);

        // Web -> RCE
        if has_web {
            let mut p = AttackPath::new("Web Application Exploitation",
                "Exploit web vulnerabilities for initial foothold", 0.7, Severity::High);
            p.add_step("Enumerate web endpoints & directories", "T1595");
            p.add_step("Identify vulnerable components (known CVEs)", "T1190");
            p.add_step("Exploit to gain remote code execution", "T1203");
            p.add_step("Establish persistent shell access", "T1059");
            paths.push(p);
        }

        // SMB -> Access
        if has_smb {
            let mut p = AttackPath::new("SMB Exploitation",
                "Leverage SMB misconfigurations for access and privilege escalation", 0.5, Severity::High);
            p.add_step("Enumerate SMB shares and users", "T1046");
            p.add_step("Check SMB signing (relay possible)", "T1557");
            p.add_step("Extract credentials or gain shell", "T1110");
            p.add_step("Lateral movement via SMB/WMI/WinRM", "T1021");
            p.add_step("Privilege escalation via service permissions", "T1574");
            paths.push(p);
        }

        // SSH
        if has_ssh {
            let mut p = AttackPath::new("SSH Credential Attack",
                "Brute-force or exploit SSH for access", 0.3, Severity::Medium);
            p.add_step("Identify SSH version & auth methods", "T1046");
            p.add_step("Test default/weak credentials", "T1110");
            p.add_step("Establish shell access", "T1059");
            paths.push(p);
        }

        // FTP
        if has_ftp {
            let mut p = AttackPath::new("FTP Abuse",
                "Anonymous access or credential brute-force on FTP", 0.4, Severity::Medium);
            p.add_step("Test anonymous FTP login", "T1046");
            p.add_step("Download files for sensitive info", "T1005");
            p.add_step("Upload malicious files if writable", "T1505");
            paths.push(p);
        }

        // Docker API
        if has_docker_api {
            let mut p = AttackPath::new("Docker Container Escape",
                "Exploit exposed Docker API for host access", 0.9, Severity::Critical);
            p.add_step("Connect to unauthenticated Docker API", "T1610");
            p.add_step("List containers and images", "T1610");
            p.add_step("Mount host filesystem from privileged container", "T1610");
            p.add_step("Full host compromise via container escape", "T1610");
            paths.push(p);
        }

        // Kubernetes
        if has_k8s {
            let mut p = AttackPath::new("Kubernetes Cluster Compromise",
                "Exploit K8s API server for cluster access", 0.8, Severity::Critical);
            p.add_step("Access Kubernetes API server", "T1610");
            p.add_step("List pods, secrets, and service accounts", "T1610");
            p.add_step("Extract service account tokens", "T1552");
            p.add_step("Deploy malicious pod for cluster compromise", "T1610");
            paths.push(p);
        }

        // Redis
        if has_redis {
            let mut p = AttackPath::new("Redis Unauthenticated Access",
                "Exploit Redis without auth for RCE or data theft", 0.8, Severity::High);
            p.add_step("Connect to Redis without authentication", "T1046");
            p.add_step("Dump keys or set SSH authorized_keys", "T1005");
            p.add_step("Achieve remote code execution via cron/SSH", "T1203");
            paths.push(p);
        }

        // RDP
        if has_rdp {
            let mut p = AttackPath::new("RDP Exploitation",
                "BlueKeep (CVE-2019-0708) or credential attack on RDP", 0.3, Severity::Critical);
            p.add_step("Identify RDP version", "T1046");
            p.add_step("Check BlueKeep / CVE-2019-0708 vulnerability", "T1190");
            p.add_step("Brute-force RDP credentials", "T1110");
            p.add_step("Establish GUI access to target", "T1021");
            paths.push(p);
        }

        // WinRM
        if has_winrm {
            let mut p = AttackPath::new("WinRM Remote Management",
                "Exploit WinRM for PowerShell remote access", 0.5, Severity::High);
            p.add_step("Enumerate WinRM endpoint", "T1046");
            p.add_step("Test default credentials", "T1110");
            p.add_step("Execute PowerShell commands remotely", "T1059");
            paths.push(p);
        }

        // Database
        if has_db {
            let mut p = AttackPath::new("Database Server Exploitation",
                "Access and extract data from databases", 0.5, Severity::High);
            p.add_step("Identify database service", "T1046");
            p.add_step("Test default credentials (root:root, sa:sa)", "T1110");
            p.add_step("Extract sensitive data via queries", "T1005");
            if self.open_ports.contains(&1433) {
                p.add_step("Attempt xp_cmdshell RCE on MSSQL", "T1203");
            }
            paths.push(p);
        }

        // NFS
        if has_nfs {
            let mut p = AttackPath::new("NFS Share Exploitation",
                "Mount NFS shares and access remote files", 0.6, Severity::Medium);
            p.add_step("Enumerate NFS exports", "T1046");
            p.add_step("Mount accessible shares locally", "T1610");
            p.add_step("Check for no_root_squash for privilege escalation", "T1574");
            paths.push(p);
        }

        // Default creds path
        if has_default_creds {
            let mut p = AttackPath::new("Default Credential Exploitation",
                "Use discovered default credentials for service access", 0.85, Severity::Critical);
            p.add_step("Discover default credentials on service", "T1110");
            p.add_step("Authenticate to service", "T1078");
            p.add_step("Extract data or execute commands", "T1203");
            p.add_step("Escalate privileges and move laterally", "T1574");
            paths.push(p);
        }

        // Score all paths (built-in + correlated) using evidence confidence
        for path in &mut paths {
            CorrelationEngine::score_path(path, &self.findings);
        }

        // Correlated attack paths from cross-module analysis
        let mut correlated = CorrelationEngine::correlate(&self.findings, &self.open_ports);
        for path in &mut correlated {
            CorrelationEngine::score_path(path, &self.findings);
        }
        paths.extend(correlated);

        paths
    }

    pub fn status_summary(&self) -> Vec<(String, TaskStatus)> {
        self.graph.node_indices()
            .map(|idx| (self.graph[idx].name.clone(), self.graph[idx].status))
            .collect()
    }

    pub fn task_count_by_status(&self) -> (usize, usize, usize, usize) {
        let mut pending = 0;
        let mut running = 0;
        let mut completed = 0;
        let mut failed = 0;
        for idx in self.graph.node_indices() {
            match self.graph[idx].status {
                TaskStatus::Pending => pending += 1,
                TaskStatus::Running => running += 1,
                TaskStatus::Completed => completed += 1,
                TaskStatus::Failed => failed += 1,
            }
        }
        (pending, running, completed, failed)
    }

    pub fn update_task_by_name(&mut self, name: &str, status: TaskStatus) {
        for idx in self.graph.node_indices() {
            if self.graph[idx].name == name {
                self.graph[idx].status = status;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::workflow::WorkflowMode;

    fn make_orchestrator() -> WorkflowOrchestrator {
        WorkflowOrchestrator::new("10.10.10.10", WorkflowMode::Beginner)
    }

    fn with_tasks(num: usize) -> WorkflowOrchestrator {
        let mut o = make_orchestrator();
        for i in 0..num {
            o.add_task(&format!("task_{}", i));
        }
        o
    }

    #[test]
    fn test_new_orchestrator_defaults() {
        let o = make_orchestrator();
        assert_eq!(o.target, "10.10.10.10");
        assert_eq!(o.mode, WorkflowMode::Beginner);
        assert!(o.open_ports.is_empty());
        assert_eq!(o.graph.node_count(), 0);
    }

    #[test]
    fn test_add_task_increases_count() {
        let mut o = make_orchestrator();
        let idx = o.add_task("port_scan");
        let node = petgraph::prelude::NodeIndex::new(idx);
        assert_eq!(o.graph.node_count(), 1);
        assert_eq!(o.graph[node].name, "port_scan");
        assert_eq!(o.graph[node].status, TaskStatus::Pending);
    }

    #[test]
    fn test_add_multiple_tasks() {
        let mut o = make_orchestrator();
        o.add_task("recon");
        o.add_task("port_scan");
        o.add_task("web");
        assert_eq!(o.graph.node_count(), 3);
    }

    #[test]
    fn test_set_open_ports() {
        let mut o = make_orchestrator();
        assert!(o.open_ports.is_empty());
        o.set_open_ports(vec![80, 443, 22]);
        assert_eq!(o.open_ports.len(), 3);
        assert!(o.open_ports.contains(&80));
    }

    #[test]
    fn test_update_task_by_name() {
        let mut o = with_tasks(3);
        o.update_task_by_name("task_1", TaskStatus::Running);
        for idx in o.graph.node_indices() {
            if o.graph[idx].name == "task_1" {
                assert_eq!(o.graph[idx].status, TaskStatus::Running);
            } else {
                assert_eq!(o.graph[idx].status, TaskStatus::Pending);
            }
        }
    }

    #[test]
    fn test_update_nonexistent_task_does_nothing() {
        let mut o = with_tasks(2);
        o.update_task_by_name("nonexistent", TaskStatus::Completed);
        // all should still be pending
        for idx in o.graph.node_indices() {
            assert_eq!(o.graph[idx].status, TaskStatus::Pending);
        }
    }

    #[test]
    fn test_update_task_by_name_updates_all_duplicates() {
        let mut o = make_orchestrator();
        o.add_task("port_scan");
        o.add_task("recon");
        o.add_task("port_scan");
        o.update_task_by_name("port_scan", TaskStatus::Completed);
        let dup_statuses: Vec<TaskStatus> = o
            .status_summary()
            .into_iter()
            .filter(|(name, _)| name == "port_scan")
            .map(|(_, status)| status)
            .collect();
        assert_eq!(dup_statuses.len(), 2);
        assert!(dup_statuses.iter().all(|s| *s == TaskStatus::Completed));
        // unrelated task untouched
        assert_eq!(o.task_count_by_status(), (1, 0, 2, 0));
    }

    #[test]
    fn test_status_summary() {
        let mut o = with_tasks(3);
        o.update_task_by_name("task_0", TaskStatus::Running);
        o.update_task_by_name("task_2", TaskStatus::Completed);
        let summary = o.status_summary();
        assert_eq!(summary.len(), 3);
        assert_eq!(summary[0], ("task_0".to_string(), TaskStatus::Running));
        assert_eq!(summary[1], ("task_1".to_string(), TaskStatus::Pending));
        assert_eq!(summary[2], ("task_2".to_string(), TaskStatus::Completed));
    }

    #[test]
    fn test_task_count_by_status_all_pending() {
        let o = with_tasks(4);
        let (p, r, c, f) = o.task_count_by_status();
        assert_eq!(p, 4);
        assert_eq!(r, 0);
        assert_eq!(c, 0);
        assert_eq!(f, 0);
    }

    #[test]
    fn test_task_count_by_status_mixed() {
        let mut o = with_tasks(5);
        o.update_task_by_name("task_0", TaskStatus::Completed);
        o.update_task_by_name("task_1", TaskStatus::Running);
        o.update_task_by_name("task_2", TaskStatus::Failed);
        let (p, r, c, f) = o.task_count_by_status();
        assert_eq!(p, 2);
        assert_eq!(r, 1);
        assert_eq!(c, 1);
        assert_eq!(f, 1);
    }

    #[test]
    fn test_generate_plan_populates_field() {
        let mut o = make_orchestrator();
        assert!(o.plan.is_none());
        o.generate_plan();
        assert!(o.plan.is_some());
        assert!(o.plan.as_ref().unwrap().name.contains("10.10.10.10"));
    }

    #[test]
    fn test_add_finding() {
        let mut o = make_orchestrator();
        let f = Finding::new("10.10.10.10", "port_scan", "Open Port: 22", "desc", Severity::Info);
        o.add_finding(f);
        assert_eq!(o.findings.findings.len(), 1);
    }

    #[test]
    fn test_generate_attack_paths_empty_ports() {
        let o = make_orchestrator();
        let paths = o.generate_attack_paths();
        assert!(paths.is_empty());
    }

    #[test]
    fn test_generate_attack_paths_with_web() {
        let mut o = make_orchestrator();
        o.set_open_ports(vec![80, 443]);
        let paths = o.generate_attack_paths();
        assert!(paths.iter().any(|p| p.name == "Web Application Exploitation"));
    }

    #[test]
    fn test_generate_attack_paths_with_smb() {
        let mut o = make_orchestrator();
        o.set_open_ports(vec![445]);
        let paths = o.generate_attack_paths();
        assert!(paths.iter().any(|p| p.name == "SMB Exploitation"));
    }

    #[test]
    fn test_generate_attack_paths_with_ssh() {
        let mut o = make_orchestrator();
        o.set_open_ports(vec![22]);
        let paths = o.generate_attack_paths();
        assert!(paths.iter().any(|p| p.name == "SSH Credential Attack"));
    }

    #[test]
    fn test_generate_attack_paths_with_ftp() {
        let mut o = make_orchestrator();
        o.set_open_ports(vec![21]);
        let paths = o.generate_attack_paths();
        assert!(paths.iter().any(|p| p.name == "FTP Abuse"));
    }

    #[test]
    fn test_generate_attack_paths_with_docker() {
        let mut o = make_orchestrator();
        o.set_open_ports(vec![2375]);
        let paths = o.generate_attack_paths();
        assert!(paths.iter().any(|p| p.name == "Docker Container Escape"));
    }

    #[test]
    fn test_generate_attack_paths_with_k8s() {
        let mut o = make_orchestrator();
        o.set_open_ports(vec![6443]);
        let paths = o.generate_attack_paths();
        assert!(paths.iter().any(|p| p.name == "Kubernetes Cluster Compromise"));
    }

    #[test]
    fn test_generate_attack_paths_with_redis() {
        let mut o = make_orchestrator();
        o.set_open_ports(vec![6379]);
        let paths = o.generate_attack_paths();
        assert!(paths.iter().any(|p| p.name == "Redis Unauthenticated Access"));
    }

    #[test]
    fn test_generate_attack_paths_with_rdp() {
        let mut o = make_orchestrator();
        o.set_open_ports(vec![3389]);
        let paths = o.generate_attack_paths();
        assert!(paths.iter().any(|p| p.name == "RDP Exploitation"));
    }

    #[test]
    fn test_generate_attack_paths_with_winrm() {
        let mut o = make_orchestrator();
        o.set_open_ports(vec![5985]);
        let paths = o.generate_attack_paths();
        assert!(paths.iter().any(|p| p.name == "WinRM Remote Management"));
    }

    #[test]
    fn test_generate_attack_paths_with_db() {
        let mut o = make_orchestrator();
        o.set_open_ports(vec![3306]);
        let paths = o.generate_attack_paths();
        assert!(paths.iter().any(|p| p.name == "Database Server Exploitation"));
    }

    #[test]
    fn test_generate_attack_paths_with_nfs() {
        let mut o = make_orchestrator();
        o.set_open_ports(vec![2049]);
        let paths = o.generate_attack_paths();
        assert!(paths.iter().any(|p| p.name == "NFS Share Exploitation"));
    }

    #[test]
    fn test_generate_attack_paths_with_default_creds() {
        let mut o = make_orchestrator();
        o.set_open_ports(vec![80]);
        let f = Finding::new("x", "creds", "Default creds", "found", Severity::Critical);
        o.add_finding(f);
        let paths = o.generate_attack_paths();
        assert!(paths.iter().any(|p| p.name == "Default Credential Exploitation"));
    }

    #[test]
    fn test_generate_attack_paths_multiple() {
        let mut o = make_orchestrator();
        o.set_open_ports(vec![22, 80, 443, 445, 3306, 6379, 3389]);
        let paths = o.generate_attack_paths();
        // Should generate web, SMB, SSH, RDP, DB, Redis paths
        assert!(paths.len() >= 6);
    }

    #[test]
    fn test_task_status_partial_eq() {
        assert_eq!(TaskStatus::Pending, TaskStatus::Pending);
        assert_ne!(TaskStatus::Pending, TaskStatus::Running);
        assert_ne!(TaskStatus::Running, TaskStatus::Completed);
        assert_ne!(TaskStatus::Completed, TaskStatus::Failed);
    }

    #[test]
    fn test_orchestrator_different_modes() {
        let modes = vec![WorkflowMode::Beginner, WorkflowMode::Professional, WorkflowMode::Ctf, WorkflowMode::Quick];
        for mode in modes {
            let o = WorkflowOrchestrator::new("test.com", mode);
            assert_eq!(o.mode, mode);
        }
    }
}
