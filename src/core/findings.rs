use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, Hash, Serialize, Deserialize, PartialEq, Eq)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Info => write!(f, "Info"),
            Severity::Low => write!(f, "Low"),
            Severity::Medium => write!(f, "Medium"),
            Severity::High => write!(f, "High"),
            Severity::Critical => write!(f, "Critical"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EducationalNote {
    pub what: String,
    pub why: String,
    pub how: String,
    pub references: Vec<String>,
    pub mitigation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub target: String,
    pub module: String,
    pub title: String,
    pub description: String,
    pub severity: Severity,
    pub confidence: f32,
    pub evidence: Vec<String>,
    pub education: Option<EducationalNote>,
    pub timestamp: String,
    pub cve: Option<String>,
}

impl Finding {
    pub fn new(target: &str, module: &str, title: &str, description: &str, severity: Severity) -> Self {
        Self {
            id: format!("{}-{}-{}", module, target, Utc::now().timestamp()),
            target: target.to_string(),
            module: module.to_string(),
            title: title.to_string(),
            description: description.to_string(),
            severity,
            confidence: 0.5,
            evidence: Vec::new(),
            education: None,
            timestamp: Utc::now().to_rfc3339(),
            cve: None,
        }
    }

    pub fn with_confidence(mut self, confidence: f32) -> Self {
        self.confidence = confidence;
        self
    }

    pub fn with_education(mut self, note: EducationalNote) -> Self {
        self.education = Some(note);
        self
    }

    pub fn with_evidence(mut self, evidence: Vec<String>) -> Self {
        self.evidence = evidence;
        self
    }

    pub fn with_cve(mut self, cve: &str) -> Self {
        self.cve = Some(cve.to_string());
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackPath {
    pub id: String,
    pub name: String,
    pub steps: Vec<AttackStep>,
    pub likelihood: f32,
    pub impact: Severity,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackStep {
    pub id: usize,
    pub description: String,
    pub technique: String,
    pub finding_refs: Vec<String>,
}

impl AttackPath {
    pub fn new(name: &str, description: &str, likelihood: f32, impact: Severity) -> Self {
        Self {
            id: format!("path-{}", Utc::now().timestamp()),
            name: name.to_string(),
            steps: Vec::new(),
            likelihood,
            impact,
            description: description.to_string(),
        }
    }

    pub fn add_step(&mut self, description: &str, technique: &str) {
        let id = self.steps.len() + 1;
        self.steps.push(AttackStep {
            id,
            description: description.to_string(),
            technique: technique.to_string(),
            finding_refs: Vec::new(),
        });
    }
}

#[derive(Clone)]
pub struct FindingStore {
    pub findings: Vec<Finding>,
    pub attack_paths: Vec<AttackPath>,
}

impl FindingStore {
    pub fn new() -> Self {
        Self { findings: Vec::new(), attack_paths: Vec::new() }
    }

    pub fn add(&mut self, finding: Finding) {
        self.findings.push(finding);
    }

    pub fn add_path(&mut self, path: AttackPath) {
        self.attack_paths.push(path);
    }

    pub fn by_module(&self, module: &str) -> Vec<&Finding> {
        self.findings.iter().filter(|f| f.module == module).collect()
    }

    pub fn count_by_severity(&self) -> [usize; 5] {
        let mut counts = [0; 5];
        for f in &self.findings {
            match f.severity {
                Severity::Info => counts[0] += 1,
                Severity::Low => counts[1] += 1,
                Severity::Medium => counts[2] += 1,
                Severity::High => counts[3] += 1,
                Severity::Critical => counts[4] += 1,
            }
        }
        counts
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_finding() {
        let f = Finding::new("10.10.10.10", "port_scan", "Open Port: 22/SSH", "Port 22 is open", Severity::Info);
        assert_eq!(f.target, "10.10.10.10");
        assert_eq!(f.module, "port_scan");
        assert_eq!(f.title, "Open Port: 22/SSH");
        assert_eq!(f.severity, Severity::Info);
        assert!(f.id.starts_with("port_scan-10.10.10.10-"));
    }

    #[test]
    fn test_finding_builder_chain() {
        let f = Finding::new("test.com", "web", "XSS", "XSS found", Severity::High)
            .with_confidence(0.9)
            .with_evidence(vec!["payload: <script>".into()])
            .with_cve("CVE-2021-1234");
        assert!((f.confidence - 0.9).abs() < 0.001);
        assert_eq!(f.evidence, vec!["payload: <script>"]);
        assert_eq!(f.cve, Some("CVE-2021-1234".into()));
    }

    #[test]
    fn test_finding_with_education() {
        let note = EducationalNote {
            what: "Test".into(),
            why: "Test".into(),
            how: "Test".into(),
            references: vec!["ref".into()],
            mitigation: "fix it".into(),
        };
        let f = Finding::new("x.com", "test", "Test", "desc", Severity::Low)
            .with_education(note);
        assert!(f.education.is_some());
        assert_eq!(f.education.as_ref().unwrap().what, "Test");
    }

    #[test]
    fn test_severity_display() {
        assert_eq!(Severity::Info.to_string(), "Info");
        assert_eq!(Severity::Low.to_string(), "Low");
        assert_eq!(Severity::Medium.to_string(), "Medium");
        assert_eq!(Severity::High.to_string(), "High");
        assert_eq!(Severity::Critical.to_string(), "Critical");
    }

    #[test]
    fn test_finding_store_add() {
        let mut store = FindingStore::new();
        let f = Finding::new("t", "m", "title", "desc", Severity::Medium);
        store.add(f);
        assert_eq!(store.findings.len(), 1);
    }

    #[test]
    fn test_finding_store_by_module() {
        let mut store = FindingStore::new();
        store.add(Finding::new("t", "web", "W1", "d", Severity::Low));
        store.add(Finding::new("t", "smb", "S1", "d", Severity::High));
        store.add(Finding::new("t", "web", "W2", "d", Severity::Info));
        let web = store.by_module("web");
        assert_eq!(web.len(), 2);
        let smb = store.by_module("smb");
        assert_eq!(smb.len(), 1);
        let none = store.by_module("nonexistent");
        assert_eq!(none.len(), 0);
    }

    #[test]
    fn test_finding_store_add_path() {
        let mut store = FindingStore::new();
        let path = AttackPath::new("Test Path", "A test", 0.5, Severity::High);
        store.add_path(path);
        assert_eq!(store.attack_paths.len(), 1);
    }

    #[test]
    fn test_attack_path_add_step() {
        let mut path = AttackPath::new("Test", "desc", 0.7, Severity::Critical);
        path.add_step("Scan ports", "T1046");
        path.add_step("Exploit", "T1203");
        assert_eq!(path.steps.len(), 2);
        assert_eq!(path.steps[0].id, 1);
        assert_eq!(path.steps[1].id, 2);
        assert_eq!(path.steps[0].technique, "T1046");
    }

    #[test]
    fn test_finding_store_count_by_severity_empty() {
        let store = FindingStore::new();
        assert_eq!(store.count_by_severity(), [0, 0, 0, 0, 0]);
    }

    #[test]
    fn test_finding_store_count_by_severity() {
        let mut store = FindingStore::new();
        store.add(Finding::new("t", "m", "I", "d", Severity::Info));
        store.add(Finding::new("t", "m", "L", "d", Severity::Low));
        store.add(Finding::new("t", "m", "M", "d", Severity::Medium));
        store.add(Finding::new("t", "m", "H", "d", Severity::High));
        store.add(Finding::new("t", "m", "C", "d", Severity::Critical));
        store.add(Finding::new("t", "m", "I2", "d", Severity::Info));
        assert_eq!(store.count_by_severity(), [2, 1, 1, 1, 1]);
    }

    #[test]
    fn test_attack_path_defaults() {
        let path = AttackPath::new("Default", "test", 0.0, Severity::Info);
        assert!(path.steps.is_empty());
        assert_eq!(path.likelihood, 0.0);
    }
}
