mod core;
mod modules;
mod ui;

use clap::Parser;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};
use std::io;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
use crate::core::adaptive::{AdaptiveEngine, Intent, ScanContext};
use crate::core::config::{RuntimeOverrides, Settings};
use crate::core::docker::{set_docker_global, DockerManager};
use crate::core::evidence::EvidenceManager;
use crate::core::findings::FindingStore;
use crate::core::orchestrator::{TaskStatus, WorkflowOrchestrator};
use crate::core::session::SessionDb;
use crate::core::target::Target;
use crate::core::vpn::VpnManager;
use crate::core::workflow::WorkflowMode;
use crate::modules::ModuleRegistry;
use crate::ui::{App, AppPhase, SetupField, Tab};

#[derive(Parser, Debug)]
#[command(
    name = "sentinel",
    version = "2.0",
    about = "Terminal-Native Offensive Security Workbench",
    long_about = "\
SENTINEL - Terminal-Native Offensive Security Workbench

A modern TUI that performs intelligent enumeration, explains findings,
prioritizes attack paths, teaches security methodology, and runs
industry-standard tools via Docker containers.

VPN Management:
  Place .ovpn (OpenVPN) or .conf (WireGuard) files in ./vpn/

Examples:
  sentinel 10.10.10.10                            Beginner mode (default)
  sentinel --ctf 10.10.10.10                      CTF mode
  sentinel --headless --quick scanme.nmap.org     Quick scan, no TUI
  sentinel --vpn htb-eu.ovpn --ctf 10.10.10.10    VPN + CTF scan
  sentinel --docker 10.10.10.10                   Use Kali Docker tools
  sentinel --vpn-list                             List available VPN configs
  sentinel --vpn wg-eu --docker --ctf target      Full pipeline with VPN + Docker
  sentinel --stealth 10.10.10.10                  Stealth mode (evasion)
  sentinel --recon-only 10.10.10.10               Recon-only mode (DNS + ports)
  sentinel --full 10.10.10.10                     Full mode (all modules)
  sentinel --exclude-ports 22,80 10.10.10.10      Skip specific ports
  sentinel --no-report 10.10.10.10                Scan without reports
  sentinel --threads 50 10.10.10.10               Override concurrency
  sentinel --rate-limit 500 target.local          Slow down probes (ms)
  sentinel --timeout 10 10.10.10.10               Override global timeout
  sentinel 10.10.10.0/24 --quick                  Multi-host CIDR scan
"
)]
struct Cli {
    /// Target IP, domain, URL, or CIDR
    target: Option<String>,

    /// CTF mode: aggressive enumeration for CTF/lab environments
    #[arg(long, short = 'c')]
    ctf: bool,

    /// Professional mode: concise output, minimal explanations
    #[arg(long, short = 'p')]
    professional: bool,

    /// Quick scan: common ports only
    #[arg(long, short = 'q')]
    quick: bool,

    /// Recon-only mode: DNS recon + port scan only, skip all other modules
    #[arg(long)]
    recon_only: bool,

    /// Full mode: maximum aggressiveness, all modules enabled regardless of CTF flag
    #[arg(long)]
    full: bool,

    /// Headless mode: no TUI, print progress to stdout
    #[arg(long, short = 'n')]
    headless: bool,

    /// VPN config file or name (from ./vpn/ directory)
    #[arg(long)]
    vpn: Option<String>,

    /// List available VPN configs from ./vpn/ and exit
    #[arg(long)]
    vpn_list: bool,

    /// Enable Docker mode — runs tools inside Kali Linux container
    #[arg(long)]
    docker: bool,

    /// Docker image to use (default: kalilinux/kali-rolling)
    #[arg(long)]
    docker_image: Option<String>,

    /// Output directory for reports (default: ./reports/)
    #[arg(long)]
    output_dir: Option<String>,

    /// JSON output for headless mode (machine-readable findings)
    #[arg(long)]
    json: bool,

    /// List past sessions from history database
    #[arg(long)]
    history: bool,

    /// Load and display a specific session by ID
    #[arg(long)]
    history_id: Option<i64>,

    /// Stealth mode (also a mode): random delays, no banner grabbing, low concurrency
    #[arg(long)]
    stealth: bool,

    /// Exclude specific ports (comma-separated, e.g. "22,80,443")
    #[arg(long)]
    exclude_ports: Option<String>,

    /// Skip report generation
    #[arg(long)]
    no_report: bool,

    /// Concurrency threads for scanning (overrides config)
    #[arg(long)]
    threads: Option<usize>,

    /// Rate limit in milliseconds between probes (overrides config)
    #[arg(long)]
    rate_limit: Option<u64>,

    /// Global timeout in seconds (overrides config)
    #[arg(long)]
    timeout: Option<u64>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()))
        .with_target(false)
        .init();

    let cli = Cli::parse();

    // Load config
    if let Ok(true) = Settings::try_load("settings.toml") {
        eprintln!("[Config] Loaded settings.toml");
    } else {
        Settings::global();
    }

    // Apply CLI overrides
    let exclude_ports: Vec<u16> = cli.exclude_ports.as_ref()
        .map(|s| s.split(',').filter_map(|p| p.trim().parse::<u16>().ok()).collect())
        .unwrap_or_default();
    RuntimeOverrides::set(RuntimeOverrides {
        exclude_ports,
        stealth_mode: cli.stealth,
        no_report: cli.no_report,
        json_mode: cli.json,
        threads: cli.threads,
        rate_limit: cli.rate_limit,
        timeout: cli.timeout,
    });

    // Handle --vpn-list
    if cli.vpn_list {
        print_vpn_list();
        return Ok(());
    }

    // Handle --history
    if cli.history || cli.history_id.is_some() {
        let db = SessionDb::new().await.unwrap_or_else(|e| {
            eprintln!("Error: Failed to open session database: {}", e);
            std::process::exit(1);
        });
        if let Some(id) = cli.history_id {
            match db.load(id).await {
                Ok(Some((target, mode, store))) => {
                    println!("Session #{}", id);
                    println!("  Target: {}", target);
                    println!("  Mode:   {}", mode);
                    println!("  Total findings: {}", store.findings.len());
                    println!("  Attack paths:   {}", store.attack_paths.len());
                    println!("\nFindings:");
                    for (i, f) in store.findings.iter().enumerate() {
                        println!("  {}. [{}] {} ({})", i + 1, f.severity, f.title, f.module);
                    }
                    if !store.attack_paths.is_empty() {
                        println!("\nAttack Paths:");
                        for (i, p) in store.attack_paths.iter().enumerate() {
                            println!("  {}. {} ({}%)", i + 1, p.name, (p.likelihood * 100.0) as u32);
                        }
                    }
                }
                Ok(None) => eprintln!("Session #{} not found", id),
                Err(e) => eprintln!("Error loading session #{}: {}", id, e),
            }
        } else {
            let sessions = db.list().await.unwrap_or_default();
            if sessions.is_empty() {
                println!("No past sessions found.");
            } else {
                println!("Past Sessions:");
                println!("  {:<4} {:<20} {:<20} {:<10} {:<12} {}", "ID", "Target", "Timestamp", "Mode", "Findings", "Paths");
                println!("  {:-<4} {:-<20} {:-<20} {:-<10} {:-<12} {:-<12}", "", "", "", "", "", "");
                for s in &sessions {
                    println!("  {:<4} {:<20} {:<20} {:<10} {:<12} {}", s.id, s.target, s.started_at, s.mode, s.total_findings, s.attack_paths);
                }
            }
        }
        return Ok(());
    }

    // In headless mode, target is required. In TUI mode, it's optional for interactive setup.
    if cli.headless && cli.target.is_none() {
        eprintln!("Error: target argument is required in headless mode");
        std::process::exit(1);
    }

    let target_str = cli.target.as_deref().unwrap_or("");
    let target = if !target_str.is_empty() {
        let t = Target::detect(target_str);
        let hosts = t.hosts();
        if hosts.len() > 1 && !cli.headless {
            eprintln!("[Target] CIDR detected: expanded to {} hosts", hosts.len());
        }
        Some(t)
    } else {
        None
    };

    let mode = if cli.ctf {
        WorkflowMode::Ctf
    } else if cli.professional {
        WorkflowMode::Professional
    } else if cli.quick {
        WorkflowMode::Quick
    } else if cli.recon_only {
        WorkflowMode::ReconOnly
    } else if cli.full {
        WorkflowMode::Full
    } else if cli.stealth {
        WorkflowMode::Stealth
    } else {
        WorkflowMode::Beginner
    };

    // Initialize VPN if requested
    let vpn_mgr = if let Some(ref vpn_config) = cli.vpn {
        let mgr = VpnManager::new();
        let config = mgr.find_config(vpn_config)
            .unwrap_or_else(|| {
                eprintln!("Error: VPN config '{}' not found in ./vpn/ directory", vpn_config);
                print_vpn_list();
                std::process::exit(1);
            });
        eprintln!("[VPN] Connecting to {} ({})...", config.name, if config.vpn_type == crate::core::vpn::VpnType::OpenVpn { "OpenVPN" } else { "WireGuard" });
        if let Err(e) = mgr.connect(&config).await {
            eprintln!("[VPN] Failed to connect: {}", e);
            eprintln!("[VPN] Continuing without VPN.");
        } else {
            let status = mgr.status.lock().await.clone();
            match status {
                crate::core::vpn::VpnStatus::Connected { interface, ip } => {
                    eprintln!("[VPN] Connected! Interface: {}, IP: {}", interface, ip);
                }
                crate::core::vpn::VpnStatus::Failed { error } => {
                    eprintln!("[VPN] Connection issue: {}", error);
                }
                _ => {}
            }
        }
        Some(Arc::new(mgr))
    } else {
        None
    };

    // Initialize Docker if requested
    let _docker_mgr = if cli.docker {
        let _ = Settings::global();
        let image = cli.docker_image.as_deref().unwrap_or_else(|| Settings::global().docker_image());
        let mgr = DockerManager::new(Some(image));
        let send = |msg: &str| eprintln!("{}", msg);
        match mgr.initialize(send).await {
            Ok(()) => {
                let mgr = Arc::new(mgr);
                set_docker_global(Some(Arc::clone(&mgr)));
                Some(mgr)
            }
            Err(e) => {
                eprintln!("[Docker] Failed to initialize: {}", e);
                eprintln!("[Docker] Continuing without Docker tools.");
                set_docker_global(None);
                None
            }
        }
    } else {
        None
    };

    // Run scan
    if cli.headless {
        let targets = target.as_ref().unwrap().hosts();
        let mut all_findings = FindingStore::new();
        let mut all_attack_paths: Vec<crate::core::findings::AttackPath> = Vec::new();
        for (i, host) in targets.iter().enumerate() {
            if targets.len() > 1 && !cli.json {
                println!("\n--- Scanning host {}/{}: {} ---", i + 1, targets.len(), host);
            }
            match run_headless(host, mode, vpn_mgr.clone(), cli.output_dir.as_deref()).await {
                Ok(Some(store)) => {
                    let paths = store.attack_paths.clone();
                    for f in store.findings { all_findings.add(f); }
                    all_attack_paths.extend(paths);
                }
                Ok(None) => {}
                Err(e) => {
                    if !cli.json { eprintln!("[ERROR] Scan of {} failed: {}", host, e); }
                }
            }
        }
        if cli.json {
            let counts = all_findings.count_by_severity();
            #[derive(serde::Serialize)]
            struct JsonOutput {
                target: String,
                mode: String,
                timestamp: String,
                summary: JsonSummary,
                findings: Vec<crate::core::findings::Finding>,
                attack_paths: Vec<crate::core::findings::AttackPath>,
                reports_dir: String,
            }
            let target_display = if targets.len() == 1 {
                targets[0].clone()
            } else {
                format!("{} targets", targets.len())
            };
            println!("{}", serde_json::to_string_pretty(&JsonOutput {
                target: target_display,
                mode: mode.to_string(),
                timestamp: chrono::Utc::now().to_rfc3339(),
                summary: JsonSummary {
                    total: all_findings.findings.len(),
                    critical: counts[4],
                    high: counts[3],
                    medium: counts[2],
                    low: counts[1],
                    info: counts[0],
                    attack_paths: all_attack_paths.len(),
                },
                findings: all_findings.findings,
                attack_paths: all_attack_paths,
                reports_dir: cli.output_dir.unwrap_or_else(|| Settings::global().report_path().to_string()),
            })?);
        } else if targets.len() > 1 {
            let counts = all_findings.count_by_severity();
            println!("\n{}", "=".repeat(50));
            println!("Scan Complete ({} targets)", targets.len());
            println!("{}", "=".repeat(50));
            println!("  Critical: {}", counts[4]);
            println!("  High:     {}", counts[3]);
            println!("  Medium:   {}", counts[2]);
            println!("  Low:      {}", counts[1]);
            println!("  Info:     {}", counts[0]);
            println!("  Total:    {}", all_findings.findings.len());
            if !all_attack_paths.is_empty() {
                println!("\nAttack Paths:");
                for (i, p) in all_attack_paths.iter().enumerate() {
                    println!("  {}. {} ({}%)", i + 1, p.name, (p.likelihood * 100.0) as u32);
                }
            }
        }
    } else {
        run_tui(target_str, mode, vpn_mgr.clone()).await?;
    }

    // Cleanup VPN
    if let Some(ref mgr) = vpn_mgr {
        eprintln!("[VPN] Disconnecting...");
        let _ = mgr.disconnect().await;
    }

    Ok(())
}

fn print_vpn_list() {
    let mgr = VpnManager::new();
    let configs = mgr.list_configs();
    if configs.is_empty() {
        eprintln!("No VPN configs found in ./vpn/");
        eprintln!("Place .ovpn (OpenVPN) or .conf (WireGuard) files in the vpn/ directory.");
        return;
    }
    eprintln!("Available VPN configs:");
    eprintln!("  {:<20} {:<10} {}", "Name", "Type", "Path");
    eprintln!("  {:-<20} {:-<10} {:-<30}", "", "", "");
    for config in &configs {
        let vpn_type = match config.vpn_type {
            crate::core::vpn::VpnType::OpenVpn => "OpenVPN",
            crate::core::vpn::VpnType::WireGuard => "WireGuard",
        };
        eprintln!("  {:<20} {:<10} {}", config.name, vpn_type, config.path.display());
    }
}

#[derive(serde::Serialize)]
struct JsonSummary {
    total: usize,
    critical: usize,
    high: usize,
    medium: usize,
    low: usize,
    info: usize,
    attack_paths: usize,
}

async fn run_headless(target: &str, mode: WorkflowMode, _vpn: Option<Arc<VpnManager>>, output_dir: Option<&str>) -> anyhow::Result<Option<FindingStore>> {
    let report_path = output_dir.unwrap_or(Settings::global().report_path());

    // Use stderr when in JSON aggregate mode so only JSON goes to stdout
    let out = || -> Box<dyn std::io::Write + Send> {
        if crate::core::config::RuntimeOverrides::global().json_mode {
            Box::new(std::io::stderr())
        } else {
            Box::new(std::io::stdout())
        }
    };

    writeln!(out(), "Sentinel - {}", mode).ok();
    writeln!(out(), "Target: {}", target).ok();
    if crate::core::docker::global_docker().is_some() {
        writeln!(out(), "[Docker] Enabled — using Kali Linux container tools").ok();
    }
    writeln!(out(), "{}", "=".repeat(50)).ok();

    let orch = Arc::new(Mutex::new(WorkflowOrchestrator::new(target, mode)));
    {
        let mut o = orch.lock().unwrap();
        for (name, _) in ModuleRegistry::build_default().all() {
            o.add_task(name);
        }
        o.generate_plan();
    }

    let (tx, mut rx) = mpsc::channel::<String>(1000);

    let tx_log = tx.clone();
    let target_str = target.to_string();
    let run_mode = mode;
    let orch_clone = Arc::clone(&orch);
    let report_path_clone = report_path.to_string();
    let scan_handle = tokio::spawn(async move {
        run_scanner(&target_str, run_mode, tx_log, orch_clone, &report_path_clone).await;
    });

    let out_print = || -> Box<dyn std::io::Write + Send> {
        if crate::core::config::RuntimeOverrides::global().json_mode {
            Box::new(std::io::stderr())
        } else {
            Box::new(std::io::stdout())
        }
    };

    let mut last_count = 0;
    loop {
        if scan_handle.is_finished() {
            while let Ok(msg) = rx.try_recv() {
                writeln!(out_print(), "{}", strip_ansi(msg)).ok();
            }
            break;
        }
        while let Ok(msg) = rx.try_recv() {
            let clean = strip_ansi(msg);
            if clean.contains("[DONE]") || clean.contains("[ERROR]") || clean.contains("[INFO]") {
                writeln!(out_print(), "{}", clean).ok();
            }
        }
        let o = orch.lock().unwrap();
        let (p, r, c, f) = o.task_count_by_status();
        let total = p + r + c + f;
        if c + f != last_count || c + f == total {
            writeln!(out_print(), "  Tasks: {} pending, {} running, {} done, {} failed ({} total)", p, r, c + f, f, total).ok();
            last_count = c + f;
        }
        drop(o);
        if c + f == total && total > 0 {
            let o = orch.lock().unwrap();
            if !o.findings.findings.is_empty() || !o.findings.attack_paths.is_empty() || !o.open_ports.is_empty() {
                break;
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }

    let _ = scan_handle.await;

    let o = orch.lock().unwrap();
    let store = o.findings.clone();
    let counts = store.count_by_severity();

    let out_summary = || -> Box<dyn std::io::Write + Send> {
        if crate::core::config::RuntimeOverrides::global().json_mode {
            Box::new(std::io::stderr())
        } else {
            Box::new(std::io::stdout())
        }
    };

    writeln!(out_summary()).ok();
    writeln!(out_summary(), "{}", "=".repeat(50)).ok();
    writeln!(out_summary(), "Scan Complete").ok();
    writeln!(out_summary(), "{}", "=".repeat(50)).ok();
    writeln!(out_summary(), "  Critical: {}", counts[4]).ok();
    writeln!(out_summary(), "  High:     {}", counts[3]).ok();
    writeln!(out_summary(), "  Medium:   {}", counts[2]).ok();
    writeln!(out_summary(), "  Low:      {}", counts[1]).ok();
    writeln!(out_summary(), "  Info:     {}", counts[0]).ok();
    writeln!(out_summary(), "  Total:    {}", store.findings.len()).ok();

    if !store.attack_paths.is_empty() {
        writeln!(out_summary()).ok();
        writeln!(out_summary(), "Attack Paths:").ok();
        for (i, p) in store.attack_paths.iter().enumerate() {
            writeln!(out_summary(), "  {}. {} ({}%)", i + 1, p.name, (p.likelihood * 100.0) as u32).ok();
        }
    }

    writeln!(out_summary()).ok();
    writeln!(out_summary(), "Findings:").ok();
    for (i, f) in store.findings.iter().enumerate() {
        writeln!(out_summary(), "  {}. [{}] {} ({})", i + 1, f.severity, f.title, f.module).ok();
    }

    if !crate::core::config::RuntimeOverrides::global().no_report {
        writeln!(out_summary(), "\nReports saved to: {}/", report_path).ok();
    }

    Ok(Some(store))
}

async fn run_tui(target: &str, mode: WorkflowMode, vpn: Option<Arc<VpnManager>>) -> anyhow::Result<()> {
    let has_target = !target.is_empty();
    let app = Arc::new(Mutex::new(App::new(target, mode, vpn)));

    // Log relay (runs for entire TUI lifetime)
    let (tx, mut rx) = mpsc::channel::<String>(1000);
    {
        let app_clone = Arc::clone(&app);
        tokio::spawn(async move {
            while let Some(msg) = rx.recv().await {
                let guard = app_clone.lock().unwrap();
                guard.add_log(msg);
            }
        });
    }

    // If target was provided at CLI, start the scan immediately
    if has_target {
        let app_clone = Arc::clone(&app);
        let tx_log = tx.clone();
        let target_str = target.to_string();
        let run_mode = mode;
        let tui_report_path = Settings::global().report_path().to_string();
        // Init orchestrator
        {
            let app_guard = app_clone.lock().unwrap();
            let mut orch = app_guard.orchestrator.lock().unwrap();
            for (name, _) in ModuleRegistry::build_default().all() {
                orch.add_task(name);
            }
            orch.generate_plan();
        }
        // Spawn scanner
        let tx_done = tx_log.clone();
        let handle = tokio::spawn(async move {
            run_scanner(&target_str, run_mode, tx_log, {
                let a = app_clone.lock().unwrap();
                Arc::clone(&a.orchestrator)
            }, &tui_report_path).await;
            let _ = tx_done.send("[TUI] Scan complete. Press q to quit.".into()).await;
        });
        app.lock().unwrap().scan_handle = Some(handle);
    }

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    terminal.clear()?;

    let res: anyhow::Result<()> = loop {
        // Draw
        {
            let app_guard = app.lock().unwrap();
            let _ = terminal.draw(|f| ui::render_ui(f, &app_guard));
        }

        // Handle events
        if event::poll(std::time::Duration::from_millis(50))? {
            if let Event::Key(key) = event::read()? {
                let mut app_guard = app.lock().unwrap();

                match app_guard.phase {
                    AppPhase::Config => {
                        match key.code {
                            KeyCode::Char('q') | KeyCode::Esc => break Ok(()),
                            KeyCode::Tab => {
                                if key.modifiers.contains(KeyModifiers::SHIFT) {
                                    app_guard.prev_field();
                                } else {
                                    app_guard.next_field();
                                }
                            }
                            KeyCode::Up => {
                                if app_guard.setup_field == SetupField::Mode {
                                    let modes = WorkflowMode::all();
                                    let len = modes.len();
                                    app_guard.selected_mode_index = (app_guard.selected_mode_index + len - 1) % len;
                                }
                            }
                            KeyCode::Down => {
                                if app_guard.setup_field == SetupField::Mode {
                                    let modes = WorkflowMode::all();
                                    app_guard.selected_mode_index = (app_guard.selected_mode_index + 1) % modes.len();
                                }
                            }
                            KeyCode::Char('?') => { app_guard.show_help = !app_guard.show_help; }
                            KeyCode::Char(' ') => { app_guard.toggle_current_field(); }
                            KeyCode::Enter => {
                                if app_guard.setup_field == SetupField::Start
                                    && !app_guard.target_input.trim().is_empty()
                                {
                                    let target_input = app_guard.target_input.trim().to_string();
                                    app_guard.apply_setup();

                                    // Init orchestrator tasks
                                    {
                                        let mut orch = app_guard.orchestrator.lock().unwrap();
                                        for (name, _) in ModuleRegistry::build_default().all() {
                                            orch.add_task(name);
                                        }
                                        orch.generate_plan();
                                    }

                                    // Spawn scanner
                                    let app_clone = Arc::clone(&app);
                                    let tx_log = tx.clone();
                                    let run_mode = app_guard.mode;
                                    let tui_report_path = Settings::global().report_path().to_string();
                                    let tx_done = tx_log.clone();
                                    let handle = tokio::spawn(async move {
                                        run_scanner(&target_input, run_mode, tx_log, {
                                            let a = app_clone.lock().unwrap();
                                            Arc::clone(&a.orchestrator)
                                        }, &tui_report_path).await;
                                        let _ = tx_done.send("[TUI] Scan complete. Press q to quit.".into()).await;
                                    });
                                    app_guard.scan_handle = Some(handle);
                                }
                            }
                            KeyCode::Char(c) => {
                                if app_guard.setup_field == SetupField::Target {
                                    app_guard.push_target_char(c);
                                }
                            }
                            KeyCode::Backspace => {
                                if app_guard.setup_field == SetupField::Target {
                                    app_guard.pop_target_char();
                                }
                            }
                            _ => {}
                        }
                    }
                    AppPhase::Running | AppPhase::Done => {
                        match key.code {
                            KeyCode::Char('q') | KeyCode::Esc => break Ok(()),
                            KeyCode::Tab => {
                                if key.modifiers.contains(KeyModifiers::SHIFT) {
                                    app_guard.prev_tab();
                                } else {
                                    app_guard.next_tab();
                                }
                            }
                            KeyCode::Up => { app_guard.scroll_up(); }
                            KeyCode::Down => { app_guard.scroll_down(); }
                            KeyCode::Enter => {
                                if app_guard.active_tab == Tab::Findings {
                                    let findings = app_guard.get_findings();
                                    let current = app_guard.selected_finding.unwrap_or(0);
                                    if !findings.is_empty() {
                                        let next = (current + 1) % findings.len();
                                        app_guard.selected_finding = Some(next);
                                        app_guard.active_tab = Tab::Education;
                                    }
                                } else if app_guard.active_tab == Tab::AttackPaths {
                                    let paths = app_guard.get_attack_paths();
                                    let current = app_guard.selected_path.unwrap_or(0);
                                    if !paths.is_empty() {
                                        let next = (current + 1) % paths.len();
                                        app_guard.selected_path = Some(next);
                                    }
                                }
                            }
                            KeyCode::Char('1') => app_guard.active_tab = Tab::Status,
                            KeyCode::Char('2') => app_guard.active_tab = Tab::Findings,
                            KeyCode::Char('3') => app_guard.active_tab = Tab::AttackPaths,
                            KeyCode::Char('4') => app_guard.active_tab = Tab::Workflow,
                            KeyCode::Char('5') => app_guard.active_tab = Tab::Education,
                            KeyCode::Char('6') => app_guard.active_tab = Tab::Log,
                            KeyCode::Char('S') => app_guard.active_tab = Tab::Setup,
                            KeyCode::Char('f') => app_guard.cycle_filter(),
                            KeyCode::Char('?') => { app_guard.show_help = !app_guard.show_help; }
                            _ => {}
                        }
                    }
                }

                if app_guard.show_help && key.code != KeyCode::Char('?') {
                    app_guard.show_help = false;
                }
            }
        }

        // Check scan completion (outside the event-handling lock)
        let is_finished = {
            let app_guard = app.lock().unwrap();
            if app_guard.phase == AppPhase::Running {
                app_guard.scan_handle.as_ref().map(|h| h.is_finished()).unwrap_or(false)
            } else {
                false
            }
        };
        if is_finished {
            let mut app_guard = app.lock().unwrap();
            app_guard.phase = AppPhase::Done;
        }
    };

    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    if let Err(e) = res {
        eprintln!("Error: {}", e);
    }

    Ok(())
}

async fn run_scanner(target: &str, mode: WorkflowMode, tx: mpsc::Sender<String>, orch: Arc<Mutex<WorkflowOrchestrator>>, report_path: &str) {
    let registry = ModuleRegistry::build_default();

    let mark_task = |name: &str, status: TaskStatus| {
        if let Ok(mut o) = orch.lock() {
            o.update_task_by_name(name, status);
        }
    };

    let phase1_modules = ["recon", "port_scan"];

    for &module_name in &phase1_modules {
        if let Some(module) = registry.get(module_name) {
            mark_task(module_name, TaskStatus::Running);
            let _ = tx.send(format!("[INFO] Starting: {} ({})", module.name(), module_name)).await;

            let result = module.execute_with_ports(target, &[], &mode, tx.clone()).await;

            match result {
                Ok(findings) => {
                    let count = findings.len();
                    let _ = tx.send(format!("[INFO] {} completed with {} findings", module.name(), count)).await;

                    if let Ok(mut o) = orch.lock() {
                        for finding in &findings {
                            o.add_finding(finding.clone());
                        }
                        if module_name == "port_scan" {
                            let port_findings: Vec<u16> = findings.iter()
                                .filter(|f| f.title.starts_with("Open Port:"))
                                .filter_map(|f| {
                                    f.title.split_whitespace().nth(2)
                                        .and_then(|s| s.split('/').next())
                                        .and_then(|s| s.parse::<u16>().ok())
                                })
                                .collect();
                            o.set_open_ports(port_findings);
                        }
                    }
                    mark_task(module_name, TaskStatus::Completed);
                }
                Err(e) => {
                    let _ = tx.send(format!("[ERROR] {} failed: {}", module.name(), e)).await;
                    mark_task(module_name, TaskStatus::Failed);
                }
            }
        }
    }

    // Phase 2: Re-generate plan with discovered ports
    let (plan, open_ports) = {
        if let Ok(mut o) = orch.lock() {
            let plan = o.generate_plan().clone();
            let open_ports = o.open_ports.clone();
            (plan, open_ports)
        } else {
            return;
        }
    };

    // Shared blackboard for adaptive chaining: modules publish discoveries
    // (e.g. proven credentials) here, and the adaptive engine reads from it.
    let scan_ctx = Arc::new(Mutex::new(ScanContext::new()));

    for step in &plan.steps {
        if phase1_modules.contains(&step.module.as_str()) || step.module == "attack_path" {
            continue;
        }

        if let Some(module) = registry.get(&step.module) {
            mark_task(&step.module, TaskStatus::Running);
            let _ = tx.send(format!("[INFO] Starting: {} ({})", step.description, step.module)).await;

            match module.execute_adaptive(target, &open_ports, &mode, &Intent::Standard, scan_ctx.clone(), tx.clone()).await {
                Ok(findings) => {
                    let count = findings.len();
                    let _ = tx.send(format!("[INFO] {} completed with {} findings", module.name(), count)).await;

                    if let Ok(mut o) = orch.lock() {
                        for finding in findings {
                            o.add_finding(finding);
                        }
                    }
                    mark_task(&step.module, TaskStatus::Completed);
                }
                Err(e) => {
                    let _ = tx.send(format!("[ERROR] {} failed: {}", module.name(), e)).await;
                    mark_task(&step.module, TaskStatus::Failed);
                }
            }
        }
    }

    // Adaptive orchestration: react to what was discovered, scheduling bounded
    // follow-up runs (credential reuse, secret harvest) that were not in the
    // static plan. Every fired trigger is logged with its rationale.
    let engine = AdaptiveEngine::default();
    for round in 1..=engine.max_rounds {
        let followups = {
            if let (Ok(o), Ok(mut c)) = (orch.lock(), scan_ctx.lock()) {
                engine.evaluate(&o.findings, &mut c, &open_ports)
            } else {
                Vec::new()
            }
        };
        if followups.is_empty() {
            break;
        }
        let _ = tx.send(format!("[CHAIN] Round {}: {} follow-up action(s) scheduled", round, followups.len())).await;
        for fu in followups {
            let _ = tx.send(format!("[CHAIN] {} → {}", fu.module, fu.rationale)).await;
            if let Some(module) = registry.get(&fu.module) {
                match module.execute_adaptive(target, &open_ports, &mode, &fu.intent, scan_ctx.clone(), tx.clone()).await {
                    Ok(findings) => {
                        let count = findings.len();
                        if let Ok(mut o) = orch.lock() {
                            for finding in findings {
                                o.add_finding(finding);
                            }
                        }
                        let _ = tx.send(format!("[CHAIN] {} follow-up produced {} finding(s)", fu.module, count)).await;
                    }
                    Err(e) => {
                        let _ = tx.send(format!("[ERROR] Chain follow-up {} failed: {}", fu.module, e)).await;
                    }
                }
            }
        }
    }

    // Generate attack paths
    let _ = tx.send("[INFO] Generating attack paths...".into()).await;
    let attack_paths = {
        if let Ok(o) = orch.lock() {
            o.generate_attack_paths()
        } else {
            Vec::new()
        }
    };

    let path_names: Vec<String> = attack_paths.iter().map(|p| p.name.clone()).collect();
    if let Ok(mut o) = orch.lock() {
        for path in attack_paths {
            o.findings.add_path(path);
        }
    }
    for name in &path_names {
        let _ = tx.send(format!("[INFO] Attack path: {} added", name)).await;
    }

    // Generate reports (skip if --no-report)
    if !RuntimeOverrides::global().no_report {
        let _ = tx.send("[INFO] Generating reports...".into()).await;
        let report_result = {
            if let Ok(o) = orch.lock() {
                let mode_str = mode.to_string();
                match EvidenceManager::with_path(target, &report_path) {
                    Ok(ev_mgr) => ev_mgr.generate_reports(&o.findings, &mode_str).map(|_| "Reports saved".to_string()),
                    Err(e) => Err(e),
                }
            } else {
                Err(anyhow::anyhow!("Orchestrator lock failed"))
            }
        };
        match &report_result {
            Ok(msg) => { let _ = tx.send(format!("[DONE] {}", msg)).await; }
            Err(e) => { let _ = tx.send(format!("[ERROR] {}", e)).await; }
        }
    } else {
        let _ = tx.send("[INFO] --no-report: skipping report generation".into()).await;
    }

    // Save session to SQLite history
    let _ = tx.send("[INFO] Saving session to history...".into()).await;
    let session_store = {
        if let Ok(o) = orch.lock() {
            FindingStore {
                findings: o.findings.findings.clone(),
                attack_paths: o.findings.attack_paths.clone(),
            }
        } else {
            FindingStore::new()
        }
    };
    if let Ok(db) = SessionDb::new().await {
        match db.save(target, &mode.to_string(), &session_store).await {
            Ok(id) => { let _ = tx.send(format!("[DONE] Session saved (id={})", id)).await; }
            Err(e) => { let _ = tx.send(format!("[ERROR] Failed to save session: {}", e)).await; }
        }
    } else {
        let _ = tx.send("[ERROR] Failed to open session database".into()).await;
    }

    let _ = tx.send("[DONE] All tasks completed.".into()).await;
}

fn strip_ansi(s: String) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            while let Some(&next) = chars.peek() {
                if next == '[' || (next >= '0' && next <= '?') || next == ';' {
                    chars.next();
                } else if (next >= '@' && next <= '~') || next == 'm' {
                    chars.next();
                    break;
                } else {
                    break;
                }
            }
        } else {
            result.push(c);
        }
    }
    result
}
