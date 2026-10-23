use crate::core::config::Settings;
use crate::core::findings::{AttackPath, Finding, FindingStore};
use chrono::Utc;
use std::fs;
use std::path::{Path, PathBuf};
use anyhow::Result;
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
pub struct Report {
    pub target: String,
    pub timestamp: String,
    pub mode: String,
    pub scan_summary: ScanSummary,
    pub findings: Vec<Finding>,
    pub attack_paths: Vec<AttackPath>,
}

#[derive(Serialize, Deserialize)]
pub struct ScanSummary {
    pub total_findings: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub info_count: usize,
    pub attack_paths: usize,
}

pub struct EvidenceManager {
    run_dir: PathBuf,
    target: String,
}

impl EvidenceManager {
    /// Create a new EvidenceManager (uses default report path from Settings)
    #[allow(dead_code)]
    pub fn new(target: &str) -> Result<Self> {
        Self::with_path(target, Settings::global().report_path())
    }

    pub fn with_path(target: &str, base_path: &str) -> Result<Self> {
        let clean_target = target.replace("/", "_").replace(":", "_").replace(".", "_");
        let timestamp = Utc::now().format("%Y%m%d_%H%M%S");
        let run_dir = Path::new(base_path).join(format!("{}_{}", clean_target, timestamp));
        fs::create_dir_all(&run_dir)?;
        fs::create_dir_all(run_dir.join("evidence"))?;
        Ok(Self { run_dir, target: target.to_string() })
    }

    pub fn generate_reports(&self, store: &FindingStore, mode: &str) -> Result<()> {
        let counts = store.count_by_severity();
        let report = Report {
            target: self.target.clone(),
            timestamp: Utc::now().to_rfc3339(),
            mode: mode.to_string(),
            scan_summary: ScanSummary {
                total_findings: store.findings.len(),
                critical_count: counts[4],
                high_count: counts[3],
                medium_count: counts[2],
                low_count: counts[1],
                info_count: counts[0],
                attack_paths: store.attack_paths.len(),
            },
            findings: store.findings.clone(),
            attack_paths: store.attack_paths.clone(),
        };

        let md = self.render_markdown(&report);
        fs::write(self.run_dir.join("report.md"), md)?;

        fs::write(self.run_dir.join("report.json"), serde_json::to_string_pretty(&report)?)?;

        fs::write(self.run_dir.join("report.yaml"), serde_yaml::to_string(&report)?)?;

        let html = self.render_html(&report);
        fs::write(self.run_dir.join("report.html"), html)?;

        let summary = self.render_summary(&report);
        fs::write(self.run_dir.join("summary.txt"), summary)?;

        Ok(())
    }

    pub(crate) fn render_markdown(&self, report: &Report) -> String {
        let mut md = String::new();
        md.push_str("# Sentinel Security Report\n\n");
        md.push_str(&format!("**Target:** {}\n", report.target));
        md.push_str(&format!("**Date:** {}\n", report.timestamp));
        md.push_str(&format!("**Mode:** {}\n\n", report.mode));

        md.push_str("## Executive Summary\n\n");
        md.push_str("| Severity | Count |\n|----------|-------|\n");
        md.push_str(&format!("| Critical | {} |\n", report.scan_summary.critical_count));
        md.push_str(&format!("| High | {} |\n", report.scan_summary.high_count));
        md.push_str(&format!("| Medium | {} |\n", report.scan_summary.medium_count));
        md.push_str(&format!("| Low | {} |\n", report.scan_summary.low_count));
        md.push_str(&format!("| Info | {} |\n", report.scan_summary.info_count));
        md.push_str(&format!("\n**Total Findings:** {}\n\n", report.scan_summary.total_findings));

        if !report.attack_paths.is_empty() {
            md.push_str("## Attack Paths\n\n");
            for (i, path) in report.attack_paths.iter().enumerate() {
                md.push_str(&format!("### {}. {}\n\n", i + 1, path.name));
                md.push_str(&format!("**Description:** {}\n", path.description));
                md.push_str(&format!("**Likelihood:** {:.0}%\n", path.likelihood * 100.0));
                md.push_str(&format!("**Impact:** {}\n\n", path.impact));
                md.push_str("**Steps:**\n");
                for step in &path.steps {
                    md.push_str(&format!("  {}. {} ({})\n", step.id, step.description, step.technique));
                }
                md.push('\n');
            }
        }

        md.push_str("## Findings\n\n");
        for (i, finding) in report.findings.iter().enumerate() {
            md.push_str(&format!("### {}. {} [{}]\n\n", i + 1, finding.title, finding.severity));
            md.push_str(&format!("**Module:** {}\n", finding.module));
            md.push_str(&format!("**Description:** {}\n", finding.description));
            if let Some(cve) = &finding.cve {
                md.push_str(&format!("**CVE:** {}\n", cve));
            }
            if let Some(edu) = &finding.education {
                md.push_str(&format!("**What is this?** {}\n", edu.what));
                md.push_str(&format!("**Why it matters:** {}\n", edu.why));
                md.push_str(&format!("**How discovered:** {}\n", edu.how));
                md.push_str(&format!("**Mitigation:** {}\n", edu.mitigation));
            }
            if !finding.evidence.is_empty() {
                md.push_str("**Evidence:**\n");
                for ev in &finding.evidence {
                    md.push_str(&format!("  - `{}`\n", ev));
                }
            }
            md.push('\n');
        }
        md
    }

    pub(crate) fn render_html(&self, report: &Report) -> String {
        let mut html = String::from("<!DOCTYPE html><html><head><meta charset='utf-8'>");
        html.push_str("<title>Sentinel Report</title>");
        html.push_str("<style>body{font-family:system-ui,sans-serif;max-width:960px;margin:2em auto;padding:0 1em;color:#333}");
        html.push_str("h1{color:#c0392b;border-bottom:2px solid #c0392b}");
        html.push_str("h2{color:#2c3e50;margin-top:2em}");
        html.push_str("h3{margin-top:1.5em}");
        html.push_str(".sev-critical{color:#e74c3c;font-weight:bold}");
        html.push_str(".sev-high{color:#e67e22;font-weight:bold}");
        html.push_str(".sev-medium{color:#f39c12}");
        html.push_str(".sev-low{color:#27ae60}");
        html.push_str(".sev-info{color:#7f8c8d}");
        html.push_str("table{border-collapse:collapse;width:100%}");
        html.push_str("td,th{border:1px solid #ddd;padding:8px;text-align:left}");
        html.push_str("tr:nth-child(even){background:#f9f9f9}");
        html.push_str("pre{background:#f4f4f4;padding:1em;overflow-x:auto}");
        html.push_str("</style></head><body>");
        html.push_str("<h1>Sentinel Security Report</h1>");
        html.push_str(&format!("<p><strong>Target:</strong> {}<br>", report.target));
        html.push_str(&format!("<strong>Date:</strong> {}<br>", report.timestamp));
        html.push_str(&format!("<strong>Mode:</strong> {}</p>", report.mode));
        html.push_str("<h2>Executive Summary</h2><table>");
        html.push_str("<tr><th>Severity</th><th>Count</th></tr>");
        html.push_str(&format!("<tr><td class='sev-critical'>Critical</td><td>{}</td></tr>", report.scan_summary.critical_count));
        html.push_str(&format!("<tr><td class='sev-high'>High</td><td>{}</td></tr>", report.scan_summary.high_count));
        html.push_str(&format!("<tr><td class='sev-medium'>Medium</td><td>{}</td></tr>", report.scan_summary.medium_count));
        html.push_str(&format!("<tr><td class='sev-low'>Low</td><td>{}</td></tr>", report.scan_summary.low_count));
        html.push_str(&format!("<tr><td class='sev-info'>Info</td><td>{}</td></tr>", report.scan_summary.info_count));
        html.push_str("</table>");

        if !report.attack_paths.is_empty() {
            html.push_str("<h2>Attack Paths</h2>");
            for (i, path) in report.attack_paths.iter().enumerate() {
                html.push_str(&format!("<h3>{}. {} (Likelihood: {:.0}%, Impact: {})</h3>", i + 1, path.name, path.likelihood * 100.0, path.impact));
                html.push_str(&format!("<p>{}</p><ol>", path.description));
                for step in &path.steps {
                    html.push_str(&format!("<li>{} <em>({})</em></li>", step.description, step.technique));
                }
                html.push_str("</ol>");
            }
        }

        html.push_str("<h2>Findings</h2>");
        for (i, finding) in report.findings.iter().enumerate() {
            let sev_class = format!("sev-{}", finding.severity).to_lowercase();
            html.push_str(&format!("<h3>{}. {} <span class='{}'>[{}]</span></h3>", i + 1, finding.title, sev_class, finding.severity));
            html.push_str(&format!("<p><strong>Module:</strong> {}<br>", finding.module));
            html.push_str(&format!("<strong>Description:</strong> {}</p>", finding.description));
            if let Some(edu) = &finding.education {
                html.push_str(&format!("<p><strong>What is this?</strong> {}<br>", edu.what));
                html.push_str(&format!("<strong>Why it matters:</strong> {}<br>", edu.why));
                html.push_str(&format!("<strong>How discovered:</strong> {}<br>", edu.how));
                html.push_str(&format!("<strong>Mitigation:</strong> {}</p>", edu.mitigation));
            }
            if !finding.evidence.is_empty() {
                html.push_str("<p><strong>Evidence:</strong></p><ul>");
                for ev in &finding.evidence {
                    html.push_str(&format!("<li><code>{}</code></li>", ev));
                }
                html.push_str("</ul>");
            }
        }
        html.push_str("</body></html>");
        html
    }

    pub(crate) fn render_summary(&self, report: &Report) -> String {
        let mut s = String::new();
        s.push_str(&format!("Sentinel Report - {}\n", report.target));
        s.push_str(&format!("{}\n", report.timestamp));
        s.push_str(&format!("Mode: {}\n", report.mode));
        s.push_str("=".repeat(50).as_str());
        s.push_str("\n\n");
        s.push_str(&format!("Critical: {}\n", report.scan_summary.critical_count));
        s.push_str(&format!("High:     {}\n", report.scan_summary.high_count));
        s.push_str(&format!("Medium:   {}\n", report.scan_summary.medium_count));
        s.push_str(&format!("Low:      {}\n", report.scan_summary.low_count));
        s.push_str(&format!("Info:     {}\n", report.scan_summary.info_count));
        s.push_str(&format!("\nTotal:    {}\n", report.scan_summary.total_findings));

        if !report.attack_paths.is_empty() {
            s.push_str("\nAttack Paths:\n");
            for (i, p) in report.attack_paths.iter().enumerate() {
                s.push_str(&format!("  {}. {} ({}%)\n", i + 1, p.name, (p.likelihood * 100.0) as u32));
            }
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::findings::{Finding, Severity, AttackPath, EducationalNote};

    fn sample_report() -> Report {
        Report {
            target: "10.10.10.10".into(),
            timestamp: "2025-01-01T00:00:00Z".into(),
            mode: "beginner".into(),
            scan_summary: ScanSummary {
                total_findings: 3,
                critical_count: 1,
                high_count: 1,
                medium_count: 0,
                low_count: 1,
                info_count: 0,
                attack_paths: 1,
            },
            findings: vec![
                Finding::new("10.10.10.10", "port_scan", "Open Port: 22/SSH", "Port 22 open", Severity::Info),
                Finding::new("10.10.10.10", "web", "Admin Panel", "Admin login found", Severity::High)
                    .with_cve("CVE-2021-1234"),
                Finding::new("10.10.10.10", "creds", "Default Credentials", "admin:admin works", Severity::Critical)
                    .with_education(EducationalNote {
                        what: "Default creds".into(),
                        why: "Easy access".into(),
                        how: "Tried common passwords".into(),
                        references: vec!["https://example.com".into()],
                        mitigation: "Change passwords".into(),
                    })
                    .with_evidence(vec!["admin:admin -> 200 OK".into()]),
            ],
            attack_paths: vec![
                {
                    let mut p = AttackPath::new("Web Exploit", "Web-based attack", 0.7, Severity::High);
                    p.add_step("Enumerate", "T1595");
                    p.add_step("Exploit", "T1203");
                    p
                },
            ],
        }
    }

    fn make_ev_mgr() -> EvidenceManager {
        EvidenceManager {
            run_dir: PathBuf::from("/tmp/sentinel-test-evidence"),
            target: "10.10.10.10".into(),
        }
    }

    #[test]
    fn test_render_markdown_contains_title() {
        let ev = make_ev_mgr();
        let report = sample_report();
        let md = ev.render_markdown(&report);
        assert!(md.contains("# Sentinel Security Report"));
        assert!(md.contains("10.10.10.10"));
        assert!(md.contains("beginner"));
    }

    #[test]
    fn test_render_markdown_severity_counts() {
        let ev = make_ev_mgr();
        let md = ev.render_markdown(&sample_report());
        assert!(md.contains("| Critical | 1 |"));
        assert!(md.contains("| High | 1 |"));
        assert!(md.contains("| Low | 1 |"));
        assert!(md.contains("| Info | 0 |"));
    }

    #[test]
    fn test_render_markdown_findings() {
        let ev = make_ev_mgr();
        let md = ev.render_markdown(&sample_report());
        assert!(md.contains("Open Port: 22/SSH"));
        assert!(md.contains("Admin Panel"));
        assert!(md.contains("Default Credentials"));
    }

    #[test]
    fn test_render_markdown_cve() {
        let ev = make_ev_mgr();
        let md = ev.render_markdown(&sample_report());
        assert!(md.contains("CVE-2021-1234"));
    }

    #[test]
    fn test_render_markdown_education() {
        let ev = make_ev_mgr();
        let md = ev.render_markdown(&sample_report());
        assert!(md.contains("Default creds"));
        assert!(md.contains("Change passwords"));
    }

    #[test]
    fn test_render_markdown_evidence() {
        let ev = make_ev_mgr();
        let md = ev.render_markdown(&sample_report());
        assert!(md.contains("admin:admin -> 200 OK"));
    }

    #[test]
    fn test_render_markdown_attack_paths() {
        let ev = make_ev_mgr();
        let md = ev.render_markdown(&sample_report());
        assert!(md.contains("## Attack Paths"));
        assert!(md.contains("Web Exploit"));
        assert!(md.contains("T1595"));
        assert!(md.contains("T1203"));
    }

    #[test]
    fn test_render_html_contains_basic_structure() {
        let ev = make_ev_mgr();
        let html = ev.render_html(&sample_report());
        assert!(html.contains("<!DOCTYPE html>"));
        assert!(html.contains("<h1>Sentinel Security Report</h1>"));
        assert!(html.contains("</html>"));
    }

    #[test]
    fn test_render_html_severity_table() {
        let ev = make_ev_mgr();
        let html = ev.render_html(&sample_report());
        assert!(html.contains("Critical"));
        assert!(html.contains("class='sev-critical'"));
        assert!(html.contains("class='sev-high'"));
        assert!(html.contains("class='sev-low'"));
    }

    #[test]
    fn test_render_html_findings() {
        let ev = make_ev_mgr();
        let html = ev.render_html(&sample_report());
        assert!(html.contains("Open Port: 22/SSH"));
        assert!(html.contains("Admin Panel"));
        assert!(html.contains("Default Credentials"));
    }

    #[test]
    fn test_render_summary_contains_counts() {
        let ev = make_ev_mgr();
        let summary = ev.render_summary(&sample_report());
        assert!(summary.contains("Critical: 1"));
        assert!(summary.contains("High:     1"));
        assert!(summary.contains("Low:      1"));
        assert!(summary.contains("Info:     0"));
        assert!(summary.contains("Total:    3"));
    }

    #[test]
    fn test_render_summary_attack_paths() {
        let ev = make_ev_mgr();
        let summary = ev.render_summary(&sample_report());
        assert!(summary.contains("Attack Paths:"));
        assert!(summary.contains("Web Exploit"));
        assert!(summary.contains("70%"));
    }

    #[test]
    fn test_generate_reports_writes_files() {
        let target = "test-evidence-write";
        let clean = target.replace("/", "_").replace(":", "_").replace(".", "_");
        let timestamp = "20250101_000000";
        // Use a unique temp dir (not the repo-relative ./reports, which may be
        // non-writable) so the test is hermetic and parallel-safe.
        let unique = format!("sentinel_evidence_test_{}_{}", std::process::id(), Utc::now().timestamp_nanos_opt().unwrap_or(0));
        let run_dir = std::env::temp_dir().join(unique).join(format!("{}_{}", clean, timestamp));
        let ev = EvidenceManager {
            run_dir: run_dir.clone(),
            target: target.into(),
        };
        // Create the run directory (normally done by new())
        std::fs::create_dir_all(&run_dir).unwrap();
        std::fs::create_dir_all(run_dir.join("evidence")).unwrap();
        let report = sample_report();
        let store = FindingStore {
            findings: report.findings,
            attack_paths: report.attack_paths,
        };
        let result = ev.generate_reports(&store, &sample_report().mode);
        assert!(result.is_ok());
        assert!(run_dir.join("report.md").exists());
        assert!(run_dir.join("report.json").exists());
        assert!(run_dir.join("report.html").exists());
        assert!(run_dir.join("report.yaml").exists());
        assert!(run_dir.join("summary.txt").exists());
        // Clean up the unique temp parent.
        if let Some(parent) = run_dir.parent() {
            let _ = std::fs::remove_dir_all(parent);
        }
    }

    #[test]
    fn test_report_serialization_json() {
        let report = sample_report();
        let json = serde_json::to_string_pretty(&report).unwrap();
        assert!(json.contains("10.10.10.10"));
        assert!(json.contains("beginner"));
        let deserialized: Report = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.target, "10.10.10.10");
        assert_eq!(deserialized.findings.len(), 3);
    }

    #[test]
    fn test_report_serialization_yaml() {
        let report = sample_report();
        let yaml = serde_yaml::to_string(&report).unwrap();
        assert!(yaml.contains("10.10.10.10"));
        let deserialized: Report = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(deserialized.target, "10.10.10.10");
    }

    #[test]
    fn test_report_empty_findings() {
        let report = Report {
            target: "empty.test".into(),
            timestamp: "2025-01-01T00:00:00Z".into(),
            mode: "quick".into(),
            scan_summary: ScanSummary {
                total_findings: 0,
                critical_count: 0,
                high_count: 0,
                medium_count: 0,
                low_count: 0,
                info_count: 0,
                attack_paths: 0,
            },
            findings: vec![],
            attack_paths: vec![],
        };
        let ev = make_ev_mgr();
        let md = ev.render_markdown(&report);
        assert!(md.contains("**Total Findings:** 0"));
        assert!(!md.contains("## Attack Paths"));
        let html = ev.render_html(&report);
        assert!(html.contains("Executive Summary"));
        let summary = ev.render_summary(&report);
        assert!(summary.contains("Total:    0"));
    }

    #[test]
    fn test_render_markdown_no_education_skips_section() {
        let report = Report {
            target: "test".into(),
            timestamp: "".into(),
            mode: "professional".into(),
            scan_summary: ScanSummary {
                total_findings: 1,
                critical_count: 0,
                high_count: 0,
                medium_count: 0,
                low_count: 0,
                info_count: 1,
                attack_paths: 0,
            },
            findings: vec![
                Finding::new("test", "port_scan", "Open Port: 80", "desc", Severity::Info),
            ],
            attack_paths: vec![],
        };
        let ev = make_ev_mgr();
        let md = ev.render_markdown(&report);
        assert!(md.contains("Open Port: 80"));
        assert!(!md.contains("What is this?"));
        assert!(!md.contains("Why it matters"));
    }
}
