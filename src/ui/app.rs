use crate::core::docker::DockerStatus;
use crate::core::findings::{AttackPath, Finding, Severity};
use crate::core::orchestrator::{TaskStatus, WorkflowOrchestrator};
use crate::core::vpn::{VpnManager, VpnStatus};
use crate::core::workflow::{WorkflowMode, WorkflowPlan};
use std::sync::{Arc, Mutex};
use std::time::Instant;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Tab {
    Setup,
    Status,
    Findings,
    AttackPaths,
    Workflow,
    Education,
    Log,
}

impl Tab {
    pub fn all() -> &'static [Tab] {
        &[
            Tab::Setup,
            Tab::Status,
            Tab::Findings,
            Tab::AttackPaths,
            Tab::Workflow,
            Tab::Education,
            Tab::Log,
        ]
    }

    pub fn name(&self) -> &'static str {
        match self {
            Tab::Setup => "Setup",
            Tab::Status => "Status",
            Tab::Findings => "Findings",
            Tab::AttackPaths => "Attack Paths",
            Tab::Workflow => "Workflow",
            Tab::Education => "Education",
            Tab::Log => "Log",
        }
    }

    pub fn key_hint(&self) -> &'static str {
        match self {
            Tab::Setup => "S",
            Tab::Status => "1",
            Tab::Findings => "2",
            Tab::AttackPaths => "3",
            Tab::Workflow => "4",
            Tab::Education => "5",
            Tab::Log => "6",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AppPhase {
    Config,
    Running,
    Done,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SetupField {
    Target,
    Mode,
    Docker,
    Stealth,
    NoReport,
    Start,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FindingFilter {
    All,
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl FindingFilter {
    pub fn all() -> &'static [FindingFilter] {
        &[Self::All, Self::Critical, Self::High, Self::Medium, Self::Low, Self::Info]
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::All => "All",
            Self::Critical => "Critical",
            Self::High => "High",
            Self::Medium => "Medium",
            Self::Low => "Low",
            Self::Info => "Info",
        }
    }

    pub fn matches(&self, sev: &Severity) -> bool {
        match self {
            Self::All => true,
            Self::Critical => *sev == Severity::Critical,
            Self::High => *sev == Severity::High,
            Self::Medium => *sev == Severity::Medium,
            Self::Low => *sev == Severity::Low,
            Self::Info => *sev == Severity::Info,
        }
    }
}

pub struct App {
    pub orchestrator: Arc<Mutex<WorkflowOrchestrator>>,
    pub logs: Arc<Mutex<Vec<String>>>,
    pub active_tab: Tab,
    pub scroll_offset: usize,
    pub selected_finding: Option<usize>,
    pub selected_path: Option<usize>,
    pub mode: WorkflowMode,
    pub target: String,
    pub show_help: bool,
    pub start_time: Instant,
    pub vpn: Option<Arc<VpnManager>>,

    // Setup phase fields
    pub phase: AppPhase,
    pub target_input: String,
    pub selected_mode_index: usize,
    pub docker_enabled: bool,
    pub stealth_enabled: bool,
    pub no_report_enabled: bool,
    pub setup_field: SetupField,
    pub scan_handle: Option<tokio::task::JoinHandle<()>>,

    // Filtering / sorting
    pub finding_filter: FindingFilter,
    pub filter_cycle_index: usize,
}

impl App {
    pub fn new(target: &str, mode: WorkflowMode, vpn: Option<Arc<VpnManager>>) -> Self {
        let has_target = !target.is_empty();
        let mode_index = WorkflowMode::all().iter().position(|m| *m == mode).unwrap_or(0);
        Self {
            orchestrator: Arc::new(Mutex::new(WorkflowOrchestrator::new(target, mode))),
            logs: Arc::new(Mutex::new(Vec::with_capacity(500))),
            active_tab: if has_target { Tab::Status } else { Tab::Setup },
            scroll_offset: 0,
            selected_finding: None,
            selected_path: None,
            mode,
            target: target.to_string(),
            show_help: false,
            start_time: Instant::now(),
            vpn,

            phase: if has_target { AppPhase::Running } else { AppPhase::Config },
            target_input: target.to_string(),
            selected_mode_index: mode_index,
            docker_enabled: crate::core::docker::global_docker().is_some(),
            stealth_enabled: crate::core::config::RuntimeOverrides::global().stealth_mode,
            no_report_enabled: crate::core::config::RuntimeOverrides::global().no_report,
            setup_field: SetupField::Target,
            scan_handle: None,
            finding_filter: FindingFilter::All,
            filter_cycle_index: 0,
        }
    }

    pub fn next_tab(&mut self) {
        let tabs = Tab::all();
        let idx = tabs.iter().position(|t| *t == self.active_tab).unwrap_or(0);
        self.active_tab = tabs[(idx + 1) % tabs.len()];
        self.scroll_offset = 0;
    }

    pub fn prev_tab(&mut self) {
        let tabs = Tab::all();
        let idx = tabs.iter().position(|t| *t == self.active_tab).unwrap_or(0);
        self.active_tab = tabs[if idx == 0 { tabs.len() - 1 } else { idx - 1 }];
        self.scroll_offset = 0;
    }

    pub fn scroll_up(&mut self) {
        self.scroll_offset = self.scroll_offset.saturating_sub(1);
    }

    pub fn scroll_down(&mut self) {
        self.scroll_offset += 1;
    }

    pub fn add_log(&self, msg: String) {
        if let Ok(mut logs) = self.logs.lock() {
            logs.push(msg);
            if logs.len() > 1000 {
                let excess = logs.len() - 1000;
                logs.drain(0..excess);
            }
        }
    }

    pub fn get_findings(&self) -> Vec<Finding> {
        self.orchestrator.lock().ok()
            .map(|o| o.findings.findings.clone())
            .unwrap_or_default()
    }

    pub fn get_attack_paths(&self) -> Vec<AttackPath> {
        self.orchestrator.lock().ok()
            .map(|o| o.findings.attack_paths.clone())
            .unwrap_or_default()
    }

    pub fn get_plan(&self) -> Option<WorkflowPlan> {
        self.orchestrator.lock().ok()
            .and_then(|o| o.plan.clone())
    }

    pub fn status_summary(&self) -> Vec<(String, TaskStatus)> {
        self.orchestrator.lock().ok()
            .map(|o| o.status_summary())
            .unwrap_or_default()
    }

    pub fn task_counts(&self) -> (usize, usize, usize, usize) {
        self.orchestrator.lock().ok()
            .map(|o| o.task_count_by_status())
            .unwrap_or_default()
    }

    pub fn get_filtered_findings(&self) -> Vec<Finding> {
        let all = self.get_findings();
        match self.finding_filter {
            FindingFilter::All => all,
            _ => all.into_iter().filter(|f| self.finding_filter.matches(&f.severity)).collect(),
        }
    }

    pub fn cycle_filter(&mut self) {
        let filters = FindingFilter::all();
        self.filter_cycle_index = (self.filter_cycle_index + 1) % filters.len();
        self.finding_filter = filters[self.filter_cycle_index];
        self.selected_finding = None;
    }

    pub fn educational_for_finding(&self, index: usize) -> Option<Finding> {
        let findings = self.get_findings();
        findings.get(index).cloned()
    }

    pub fn elapsed_str(&self) -> String {
        let d = self.start_time.elapsed();
        let secs = d.as_secs();
        let h = secs / 3600;
        let m = (secs % 3600) / 60;
        let s = secs % 60;
        format!("{:02}:{:02}:{:02}", h, m, s)
    }

    pub fn vpn_status_str(&self) -> String {
        self.vpn.as_ref().map(|v| {
            match v.status.try_lock() {
                Ok(status) => match &*status {
                    VpnStatus::Connected { interface, ip } => format!("VPN {} ({})", interface, ip),
                    VpnStatus::Connecting => "VPN connecting...".into(),
                    VpnStatus::Disconnected => "VPN off".into(),
                    VpnStatus::Failed { error } => format!("VPN err: {}", error),
                },
                Err(_) => "VPN ...".into(),
            }
        }).unwrap_or_else(|| String::new())
    }

    pub fn docker_status_str(&self) -> String {
        match crate::core::docker::global_docker() {
            Some(mgr) => match mgr.status.try_lock() {
                Ok(status) => match &*status {
                    DockerStatus::Ready { image, .. } => {
                        let short = image.rsplit('/').next().unwrap_or(image);
                        format!("Docker: {}", short)
                    },
                    DockerStatus::Pulling => "Docker pulling...".into(),
                    DockerStatus::Unavailable => "Docker off".into(),
                    DockerStatus::Failed { error } => format!("Docker err: {}", error),
                },
                Err(_) => "Docker ...".into(),
            },
            None => String::new(),
        }
    }

    pub fn has_vpn(&self) -> bool {
        self.vpn.is_some()
    }

    pub fn has_docker(&self) -> bool {
        crate::core::docker::global_docker().is_some()
    }

    /// Move to next setup field
    pub fn next_field(&mut self) {
        self.setup_field = match self.setup_field {
            SetupField::Target => SetupField::Mode,
            SetupField::Mode => SetupField::Docker,
            SetupField::Docker => SetupField::Stealth,
            SetupField::Stealth => SetupField::NoReport,
            SetupField::NoReport => SetupField::Start,
            SetupField::Start => SetupField::Target,
        };
    }

    /// Move to previous setup field
    pub fn prev_field(&mut self) {
        self.setup_field = match self.setup_field {
            SetupField::Target => SetupField::Start,
            SetupField::Mode => SetupField::Target,
            SetupField::Docker => SetupField::Mode,
            SetupField::Stealth => SetupField::Docker,
            SetupField::NoReport => SetupField::Stealth,
            SetupField::Start => SetupField::NoReport,
        };
    }

    /// Toggle the current boolean field
    pub fn toggle_current_field(&mut self) {
        match self.setup_field {
            SetupField::Docker => self.docker_enabled = !self.docker_enabled,
            SetupField::Stealth => self.stealth_enabled = !self.stealth_enabled,
            SetupField::NoReport => self.no_report_enabled = !self.no_report_enabled,
            _ => {}
        }
    }

    /// Update target input with a character
    pub fn push_target_char(&mut self, c: char) {
        self.target_input.push(c);
    }

    /// Remove last character from target input
    pub fn pop_target_char(&mut self) {
        self.target_input.pop();
    }

    /// Apply setup config and start the scan
    pub fn apply_setup(&mut self) {
        let target = if self.target_input.trim().is_empty() {
            "127.0.0.1".to_string()
        } else {
            self.target_input.trim().to_string()
        };
        self.target = target.clone();
        let modes = WorkflowMode::all();
        self.mode = modes[self.selected_mode_index.min(modes.len() - 1)];

        // Apply runtime overrides from setup
        crate::core::config::RuntimeOverrides::update(|rt| {
            if self.stealth_enabled {
                rt.stealth_mode = true;
            }
            rt.no_report = self.no_report_enabled;
        });

        self.orchestrator = Arc::new(Mutex::new(WorkflowOrchestrator::new(&target, self.mode)));
        self.phase = AppPhase::Running;
        self.active_tab = Tab::Status;
        self.start_time = Instant::now();
    }
}
