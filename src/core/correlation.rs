use crate::core::findings::{AttackPath, Finding, FindingStore, Severity};
use std::collections::HashMap;

pub struct CorrelationEngine;

impl CorrelationEngine {
    /// Correlate findings across modules to generate smarter attack paths
    /// that combine evidence from multiple sources.
    pub fn correlate(store: &FindingStore, open_ports: &[u16]) -> Vec<AttackPath> {
        let mut paths = Vec::new();
        let by_module = Self::group_by_module(store);

        let found_creds = Self::get_finding_titles(&by_module, "creds");
        let web_findings = Self::get_finding_titles(&by_module, "web");
        let smb_findings = Self::get_finding_titles(&by_module, "smb");
        let exploit_findings = Self::get_finding_titles(&by_module, "exploit");

        let has_creds = !found_creds.is_empty();
        let has_web = !web_findings.is_empty();
        let has_smb = !smb_findings.is_empty();

        let has_admin_creds = found_creds.iter().any(|t| t.to_lowercase().contains("admin"));
        let has_web_panel = web_findings.iter().any(|t| {
            let lc = t.to_lowercase();
            lc.contains("admin") || lc.contains("panel") || lc.contains("login") || lc.contains("wp-admin")
        });
        let has_git_exposure = web_findings.iter().any(|t| t.contains(".git"));
        let has_env_exposure = web_findings.iter().any(|t| t.contains(".env"));
        let has_phpmyadmin = web_findings.iter().any(|t| t.to_lowercase().contains("phpmyadmin"));

        // Path 1: Credentialed Web Access (creds + web panel)
        if has_creds && has_web_panel {
            let mut p = AttackPath::new(
                "Credentialed Web Access",
                "Default/admin credentials discovered for a web control panel — immediate authenticated access.",
                0.9,
                Severity::Critical,
            );
            p.add_step("Discover web admin panel", "T1595");
            p.add_step("Test default credentials against panel", "T1110");
            p.add_step("Authenticate with discovered credentials", "T1078");
            p.add_step("Extract data or escalate via admin functions", "T1203");
            paths.push(p);
        }

        // Path 2: Git/Env Exposure + Creds → Data Breach
        if (has_git_exposure || has_env_exposure) && has_creds {
            let mut p = AttackPath::new(
                "Credential Leak via Source Exposure",
                "Exposed .git or .env files combined with discovered credentials — sensitive data leakage confirmed.",
                0.85,
                Severity::Critical,
            );
            p.add_step("Discover exposed .git/.env directory", "T1595");
            p.add_step("Extract credentials from exposed files", "T1552");
            p.add_step("Use extracted credentials for lateral movement", "T1078");
            p.add_step("Access additional systems with leaked creds", "T1021");
            paths.push(p);
        }

        // Path 3: SMB + Creds → Full Domain Access
        if has_smb && has_admin_creds {
            let mut p = AttackPath::new(
                "SMB Authenticated Access",
                "SMB null session or credentials discovered allows remote file access and potential code execution.",
                0.85,
                Severity::Critical,
            );
            p.add_step("Enumerate SMB shares", "T1046");
            p.add_step("Authenticate with discovered credentials", "T1078");
            p.add_step("Access sensitive files via SMB shares", "T1005");
            p.add_step("Deploy payload via writable share", "T1505");
            paths.push(p);
        }

        // Path 4: Web App + Database → SQLi Impact Chain
        if has_web && open_ports.iter().any(|p| [3306, 5432, 1433, 27017].contains(p)) {
            let mut p = AttackPath::new(
                "Web + Database Attack Chain",
                "Web application combined with database service suggests SQL injection or direct DB access potential.",
                0.75,
                Severity::High,
            );
            p.add_step("Enumerate web application endpoints", "T1595");
            p.add_step("Test for SQL injection vulnerabilities", "T1190");
            p.add_step("Extract data from backend database", "T1005");
            p.add_step("Escalate privileges via DB function calls", "T1203");
            paths.push(p);
        }

        // Path 5: Exposed Admin Panels (phpmyadmin, adminer, etc.)
        if has_phpmyadmin {
            let mut p = AttackPath::new(
                "Database Admin Panel Exploitation",
                "phpMyAdmin or similar database admin panel exposed — common target for credential brute-force.",
                0.8,
                Severity::Critical,
            );
            p.add_step("Discover database admin panel", "T1595");
            p.add_step("Test default/weak credentials", "T1110");
            p.add_step("Execute SQL queries via panel", "T1203");
            p.add_step("Extract all database contents", "T1005");
            paths.push(p);
        }

        // Path 6: Web + Exploit findings → Targeted Exploitation
        if has_web && !exploit_findings.is_empty() {
            let cve_refs: Vec<String> = exploit_findings.iter()
                .filter(|t| t.contains("CVE"))
                .map(|t| t.clone())
                .collect();
            if !cve_refs.is_empty() {
                let mut p = AttackPath::new(
                    "CVE-Based Web Exploitation",
                    &format!("Web application vulnerabilities with {} known CVEs mapped — targeted exploitation feasible.", cve_refs.len()),
                    0.8,
                    Severity::Critical,
                );
                p.add_step("Map CVE to exploit module", "T1190");
                p.add_step("Deploy exploit against vulnerable service", "T1203");
                p.add_step("Establish initial foothold", "T1059");
                p.add_step("Pivot to internal network", "T1021");
                paths.push(p);
            }
        }

        // Path 7: SMB + No Creds → Null Session Abuse
        if has_smb {
            let null_sessions = store.findings.iter()
                .filter(|f| f.module == "smb" && f.title.contains("Null Session") && f.severity == Severity::Critical);
            let accessible_shares = store.findings.iter()
                .filter(|f| f.module == "smb" && f.title.contains("Accessible Share"));

            if null_sessions.count() > 0 {
                let share_count = accessible_shares.count();
                let mut p = AttackPath::new(
                    "SMB Null Session Data Harvesting",
                    &format!("Null session access to SMB with {} accessible shares — potential sensitive data exposure.", share_count),
                    0.75,
                    Severity::High,
                );
                p.add_step("Establish null session", "T1046");
                p.add_step("Enumerate accessible shares", "T1046");
                p.add_step("Download sensitive files from shares", "T1005");
                p.add_step("Extract credentials from SAM/SYSVOL", "T1003");
                paths.push(p);
            }
        }

        // Path 8: Docker API + Internal Network → Container Escape
        if open_ports.contains(&2375) || open_ports.contains(&2376) {
            let mut p = AttackPath::new(
                "Exposed Docker API Exploitation",
                "Docker TCP API exposed — immediate host-level compromise via container escape.",
                0.9,
                Severity::Critical,
            );
            p.add_step("Connect to Docker API without auth", "T1610");
            p.add_step("List running containers and images", "T1610");
            p.add_step("Mount host filesystem from privileged container", "T1610");
            p.add_step("Extract SSH keys and credentials from host", "T1552");
            p.add_step("Full host compromise via container escape", "T1610");
            paths.push(p);
        }

        // Path 9: Multiple Admin Interfaces → Full Management Access
        let admin_interface_count = web_findings.iter()
            .filter(|t| t.to_lowercase().contains("admin"))
            .count();
        if admin_interface_count >= 2 {
            let mut p = AttackPath::new(
                "Multiple Admin Interfaces Discovered",
                &format!("{} admin interfaces found on target — broad attack surface for credential attacks.", admin_interface_count),
                0.7,
                Severity::High,
            );
            p.add_step("Map all admin interfaces", "T1595");
            p.add_step("Test credential reuse across interfaces", "T1110");
            p.add_step("Gain access to multiple management panels", "T1078");
            p.add_step("Escalate privileges via combined access", "T1574");
            paths.push(p);
        }

        // Path 10: Flag Hunting (CTF-specific)
        let flag_findings: Vec<&Finding> = store.findings.iter()
            .filter(|f| f.title.contains("FLAG") || f.title.contains("Flag"))
            .collect();
        if !flag_findings.is_empty() {
            let mut p = AttackPath::new(
                "Flag Capture Path",
                &format!("{} flags discovered during enumeration. Follow the exploitation chain to capture remaining flags.", flag_findings.len()),
                0.95,
                Severity::Critical,
            );
            for f in &flag_findings {
                p.add_step(&format!("Capture: {} — {}", f.title, f.description.chars().take(80).collect::<String>()), "FLAG_CAPTURE");
            }
            p.add_step("Consolidate all captured flags", "FLAG_CAPTURE");
            paths.push(p);
        }

        paths
    }

    /// Score attack paths based on actual evidence weight from findings,
    /// incorporating individual finding confidence values.
    /// Paths with high-confidence findings get a larger boost.
    pub fn score_path(path: &mut AttackPath, store: &FindingStore) {
        let total = store.findings.len();
        if total == 0 {
            return;
        }

        let avg_confidence: f32 = store.findings.iter().map(|f| f.confidence).sum::<f32>() / total as f32;

        let evidence_weight = (total as f32 * 0.03).min(0.15) * avg_confidence;
        let cred_count = store.by_module("creds").len() as f32;
        let exploit_count = store.by_module("exploit").len() as f32;
        let cred_weight = (cred_count * 0.08).min(0.15) * avg_confidence;
        let exploit_weight = (exploit_count * 0.06).min(0.10) * avg_confidence;

        // Penalize if confidence is very low (< 0.3) — unreliable findings should not boost paths
        let reliability_penalty = if avg_confidence < 0.3 { avg_confidence * 0.5 } else { 0.0 };

        let adjustment = (evidence_weight + cred_weight + exploit_weight - reliability_penalty)
            .max(0.0)
            .min(0.25);
        path.likelihood = (path.likelihood + adjustment).min(0.99);
    }

    fn group_by_module(store: &FindingStore) -> HashMap<String, Vec<&Finding>> {
        let mut map: HashMap<String, Vec<&Finding>> = HashMap::new();
        for f in &store.findings {
            map.entry(f.module.clone()).or_default().push(f);
        }
        map
    }

    fn get_finding_titles<'a>(by_module: &HashMap<String, Vec<&'a Finding>>, module: &str) -> Vec<String> {
        by_module.get(module)
            .map(|findings| findings.iter().map(|f| f.title.clone()).collect())
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_store() -> FindingStore {
        FindingStore::new()
    }

    fn add_finding(store: &mut FindingStore, module: &str, title: &str, severity: Severity) {
        store.add(Finding::new("test.local", module, title, "test description", severity));
    }

    #[test]
    fn test_correlate_empty_store() {
        let store = make_store();
        let paths = CorrelationEngine::correlate(&store, &[]);
        assert!(paths.is_empty());
    }

    #[test]
    fn test_correlate_creds_and_web_panel() {
        let mut store = make_store();
        add_finding(&mut store, "web", "Admin Panel Found", Severity::High);
        add_finding(&mut store, "creds", "admin:admin on HTTP", Severity::Critical);
        let paths = CorrelationEngine::correlate(&store, &[80]);
        assert!(paths.iter().any(|p| p.name == "Credentialed Web Access"));
    }

    #[test]
    fn test_correlate_git_and_creds() {
        let mut store = make_store();
        add_finding(&mut store, "web", ".git directory exposed", Severity::High);
        add_finding(&mut store, "creds", "root:root on SSH", Severity::Critical);
        let paths = CorrelationEngine::correlate(&store, &[22]);
        assert!(paths.iter().any(|p| p.name == "Credential Leak via Source Exposure"));
    }

    #[test]
    fn test_correlate_smb_and_admin_creds() {
        let mut store = make_store();
        add_finding(&mut store, "smb", "SMB Signing Disabled", Severity::Medium);
        add_finding(&mut store, "creds", "admin:admin on SMB", Severity::Critical);
        let paths = CorrelationEngine::correlate(&store, &[445]);
        assert!(paths.iter().any(|p| p.name == "SMB Authenticated Access"));
    }

    #[test]
    fn test_correlate_web_and_db() {
        let mut store = make_store();
        add_finding(&mut store, "web", "Web Application Found", Severity::Info);
        let paths = CorrelationEngine::correlate(&store, &[80, 3306]);
        assert!(paths.iter().any(|p| p.name == "Web + Database Attack Chain"));
    }

    #[test]
    fn test_correlate_phpmyadmin() {
        let mut store = make_store();
        add_finding(&mut store, "web", "phpmyadmin panel found", Severity::High);
        let paths = CorrelationEngine::correlate(&store, &[80]);
        assert!(paths.iter().any(|p| p.name == "Database Admin Panel Exploitation"));
    }

    #[test]
    fn test_correlate_docker_api() {
        let store = make_store();
        let paths = CorrelationEngine::correlate(&store, &[2375]);
        assert!(paths.iter().any(|p| p.name == "Exposed Docker API Exploitation"));
    }

    #[test]
    fn test_correlate_multiple_admin_interfaces() {
        let mut store = make_store();
        add_finding(&mut store, "web", "Admin Login Found", Severity::Medium);
        add_finding(&mut store, "web", "Admin Dashboard", Severity::Low);
        let paths = CorrelationEngine::correlate(&store, &[80]);
        assert!(paths.iter().any(|p| p.name == "Multiple Admin Interfaces Discovered"));
    }

    #[test]
    fn test_correlate_flag_hunting() {
        let mut store = make_store();
        add_finding(&mut store, "web", "FLAG FOUND: HTB{test_flag}", Severity::Critical);
        let paths = CorrelationEngine::correlate(&store, &[80]);
        assert!(paths.iter().any(|p| p.name == "Flag Capture Path"));
    }

    #[test]
    fn test_score_path_increases_likelihood() {
        let mut store = make_store();
        for i in 0..5 {
            let mut f = Finding::new("test.local", "port_scan", &format!("Open Port: {}", i), "desc", Severity::Info);
            f.confidence = 0.9;
            store.add(f);
        }
        let mut path = AttackPath::new("Test Path", "test", 0.5, Severity::High);
        CorrelationEngine::score_path(&mut path, &store);
        assert!(path.likelihood > 0.5);
        assert!(path.likelihood <= 0.99);
    }

    #[test]
    fn test_score_path_empty_store_no_change() {
        let store = make_store();
        let mut path = AttackPath::new("Test Path", "test", 0.5, Severity::High);
        CorrelationEngine::score_path(&mut path, &store);
        // Empty store should leave likelihood unchanged
        assert!((path.likelihood - 0.5).abs() < 0.001);
    }

    #[test]
    fn test_score_path_high_confidence_boosts_more() {
        let mut store_low = make_store();
        let mut store_high = make_store();
        for i in 0..5 {
            let mut f_low = Finding::new("test.local", "port_scan", &format!("Port: {}", i), "desc", Severity::Info);
            f_low.confidence = 0.3;
            store_low.add(f_low);

            let mut f_high = Finding::new("test.local", "port_scan", &format!("Port: {}", i), "desc", Severity::Info);
            f_high.confidence = 0.95;
            store_high.add(f_high);
        }
        let mut path_low = AttackPath::new("Low Conf", "test", 0.5, Severity::High);
        let mut path_high = AttackPath::new("High Conf", "test", 0.5, Severity::High);
        CorrelationEngine::score_path(&mut path_low, &store_low);
        CorrelationEngine::score_path(&mut path_high, &store_high);
        assert!(path_high.likelihood > path_low.likelihood);
    }

    #[test]
    fn test_correlate_smb_null_session() {
        let mut store = make_store();
        add_finding(&mut store, "smb", "SMB Null Session Allowed", Severity::Critical);
        add_finding(&mut store, "smb", "SMB Accessible Share: DATA", Severity::High);
        let paths = CorrelationEngine::correlate(&store, &[445]);
        assert!(paths.iter().any(|p| p.name == "SMB Null Session Data Harvesting"));
    }

    #[test]
    fn test_correlate_cve_based_web_exploitation() {
        let mut store = make_store();
        add_finding(&mut store, "web", "Web Server Found", Severity::Info);
        add_finding(&mut store, "exploit", "CVE-2024-6387 on port 22", Severity::High);
        let paths = CorrelationEngine::correlate(&store, &[80]);
        assert!(paths.iter().any(|p| p.name == "CVE-Based Web Exploitation"));
    }

    #[test]
    fn test_group_by_module_empty() {
        let store = make_store();
        let grouped = CorrelationEngine::group_by_module(&store);
        assert!(grouped.is_empty());
    }

    #[test]
    fn test_group_by_module_multiple() {
        let mut store = make_store();
        add_finding(&mut store, "web", "A", Severity::Info);
        add_finding(&mut store, "smb", "B", Severity::Info);
        add_finding(&mut store, "web", "C", Severity::Info);
        let grouped = CorrelationEngine::group_by_module(&store);
        assert_eq!(grouped.get("web").unwrap().len(), 2);
        assert_eq!(grouped.get("smb").unwrap().len(), 1);
    }
}
