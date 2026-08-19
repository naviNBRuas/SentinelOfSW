mod app;
pub use app::{App, AppPhase, SetupField, Tab, FindingFilter};

use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span, Text},
    widgets::{
        Block, BorderType, Borders, Clear, List, ListItem, Paragraph, Tabs,
        Gauge,
    },
    Frame,
};
use crate::core::findings::{Finding, Severity};
use crate::core::orchestrator::TaskStatus;
use crate::core::workflow::WorkflowMode;

// ── Colour palette ──────────────────────────────────────────
const C_FG: Color = Color::White;
const C_DIM: Color = Color::DarkGray;
const C_ACCENT: Color = Color::Cyan;
const C_ACCENT2: Color = Color::Magenta;
const C_GREEN: Color = Color::Green;
const C_YELLOW: Color = Color::Yellow;
const C_RED: Color = Color::Red;
const C_LRED: Color = Color::LightRed;
const C_LBLUE: Color = Color::LightBlue;
const C_LMAG: Color = Color::LightMagenta;

fn severity_color(sev: &Severity) -> Color {
    match sev {
        Severity::Critical => C_RED,
        Severity::High => C_LRED,
        Severity::Medium => C_YELLOW,
        Severity::Low => C_GREEN,
        Severity::Info => C_DIM,
    }
}

fn mode_style(mode: WorkflowMode) -> (Color, &'static str, &'static str) {
    match mode {
        WorkflowMode::Beginner => (C_GREEN, "BEGINNER", "●"),
        WorkflowMode::Professional => (C_LBLUE, "PRO", "●"),
        WorkflowMode::Ctf => (C_RED, "CTF", "●"),
        WorkflowMode::Quick => (C_YELLOW, "QUICK", "●"),
        WorkflowMode::Stealth => (C_DIM, "STEALTH", "●"),
        WorkflowMode::ReconOnly => (C_ACCENT2, "RECON", "●"),
        WorkflowMode::Full => (C_LMAG, "FULL", "●"),
    }
}

fn bordered(title: String, color: Color) -> Block<'static> {
    Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(color))
}

fn render_header(f: &mut Frame, area: Rect, app: &App) {
    let (mode_color, mode_name, mode_dot) = mode_style(app.mode);
    let mode_label = if app.phase == AppPhase::Config { "SETUP" } else { mode_name };

    let header = Paragraph::new(Line::from(vec![
        Span::raw("  "),
        Span::styled("SENTINEL", Style::default().fg(C_ACCENT).add_modifier(Modifier::BOLD)),
        Span::styled(" SECURITY WORKBENCH ", Style::default().fg(C_DIM)),
        Span::styled("│", Style::default().fg(C_DIM)),
        Span::raw(" "),
        Span::styled(mode_dot, Style::default().fg(if app.phase == AppPhase::Config { C_DIM } else { mode_color })),
        Span::raw(" "),
        Span::styled(mode_label, Style::default().fg(if app.phase == AppPhase::Config { C_DIM } else { mode_color }).add_modifier(Modifier::BOLD)),
        Span::raw("  "),
        Span::styled("│", Style::default().fg(C_DIM)),
        Span::raw("  "),
        Span::styled("Target:", Style::default().fg(C_DIM)),
        Span::raw(" "),
        Span::styled(if app.target.is_empty() { "(not set)" } else { &app.target }, Style::default().fg(C_FG).add_modifier(Modifier::BOLD)),
        Span::raw("  "),
        Span::styled("│", Style::default().fg(C_DIM)),
        Span::raw("  "),
        Span::styled("Elapsed:", Style::default().fg(C_DIM)),
        Span::raw(" "),
        Span::styled(app.elapsed_str(), Style::default().fg(C_ACCENT)),
    ]))
    .style(Style::default().bg(Color::Black))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Thick)
            .border_style(Style::default().fg(C_ACCENT)),
    );
    f.render_widget(header, area);
}

fn render_tab_bar(f: &mut Frame, area: Rect, app: &App) {
    let active_tabs: &[Tab] = if app.phase == AppPhase::Config {
        &[Tab::Setup]
    } else {
        Tab::all()
    };

    let titles: Vec<Line> = active_tabs
        .iter()
        .map(|tab| {
            let is_active = *tab == app.active_tab;
            let name = tab.name();
            let badge = match tab {
                Tab::Findings => format!(" ({})", app.get_findings().len()),
                Tab::AttackPaths => format!(" ({})", app.get_attack_paths().len()),
                _ => String::new(),
            };
            let label = format!(" {} {} ", tab.key_hint(), name);
            let full = format!("{}{}", label, badge);

            if is_active {
                Line::from(Span::styled(
                    full,
                    Style::default()
                        .fg(Color::Black)
                        .bg(C_ACCENT)
                        .add_modifier(Modifier::BOLD),
                ))
            } else {
                Line::from(Span::styled(
                    full,
                    Style::default().fg(C_DIM),
                ))
            }
        })
        .collect();

    let tabs = Tabs::new(titles)
        .select(
            active_tabs.iter().position(|t| *t == app.active_tab).unwrap_or(0),
        )
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(C_DIM)),
        );
    f.render_widget(tabs, area);
}

fn render_sidebar(f: &mut Frame, area: Rect, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(10),
            Constraint::Length(5),
            Constraint::Length(7),
            Constraint::Min(6),
        ])
        .split(area);

    render_sidebar_target(f, chunks[0], app);
    render_sidebar_progress(f, chunks[1], app);
    render_sidebar_tasks(f, chunks[2], app);
    render_sidebar_legend(f, chunks[3], app);
}

fn render_sidebar_target(f: &mut Frame, area: Rect, app: &App) {
    let (mode_color, mode_name, _) = mode_style(app.mode);
    let block = bordered(" Target ".into(), C_ACCENT);
    let inner = block.inner(area);
    f.render_widget(block, area);

    let vpn_line = if app.has_vpn() {
        Some(Line::from(vec![
            Span::styled("VPN:   ", Style::default().fg(C_DIM)),
            Span::styled(app.vpn_status_str(), Style::default().fg(C_GREEN)),
        ]))
    } else {
        None
    };

    let docker_line = if app.has_docker() {
        Some(Line::from(vec![
            Span::styled("Docker:", Style::default().fg(C_DIM)),
            Span::styled(format!(" {}", app.docker_status_str()), Style::default().fg(C_YELLOW)),
        ]))
    } else {
        None
    };

    let mut lines = vec![
        Line::from(vec![
            Span::styled("Host:  ", Style::default().fg(C_DIM)),
            Span::styled(if app.target.is_empty() { "(not set)" } else { &app.target }, Style::default().fg(C_FG).add_modifier(Modifier::BOLD)),
        ]),
        Line::from(vec![
            Span::styled("Mode:  ", Style::default().fg(C_DIM)),
            Span::styled(mode_name, Style::default().fg(mode_color).add_modifier(Modifier::BOLD)),
        ]),
        Line::from(vec![
            Span::styled("Time:  ", Style::default().fg(C_DIM)),
            Span::styled(app.elapsed_str(), Style::default().fg(C_ACCENT)),
        ]),
    ];
    if let Some(line) = vpn_line {
        lines.push(line);
    }
    if let Some(line) = docker_line {
        lines.push(line);
    }

    let para = Paragraph::new(Text::from(lines)).style(Style::default());
    f.render_widget(para, inner);
}

fn render_sidebar_progress(f: &mut Frame, area: Rect, app: &App) {
    let block = bordered(" Progress ".into(), C_ACCENT);
    let inner = block.inner(area);
    f.render_widget(block, area);

    let (pending, running, completed, failed) = app.task_counts();
    let total = pending + running + completed + failed;
    let pct = if total > 0 { completed as f64 / total as f64 } else { 0.0 };

    let gauge = Gauge::default()
        .ratio(pct)
        .label(format!("{:.0}%", pct * 100.0))
        .style(Style::default().fg(C_ACCENT))
        .gauge_style(
            Style::default()
                .fg(match pct {
                    _ if pct >= 1.0 => C_GREEN,
                    _ if pct >= 0.5 => C_YELLOW,
                    _ => C_ACCENT,
                })
                .bg(Color::DarkGray),
        );
    f.render_widget(gauge, Rect::new(inner.x, inner.y, inner.width, 1));

    let lines = vec![
        Line::from(Span::styled(format!("{} / {} tasks", completed, total), Style::default().fg(C_DIM))),
    ];
    let para = Paragraph::new(Text::from(lines)).style(Style::default());
    f.render_widget(para, Rect::new(inner.x, inner.y + 2, inner.width, 2));
}

fn render_sidebar_tasks(f: &mut Frame, area: Rect, app: &App) {
    let block = bordered(" Tasks ".into(), C_ACCENT);
    let inner = block.inner(area);
    f.render_widget(block, area);

    let (pending, running, completed, failed) = app.task_counts();
    let lines = vec![
        Line::from(vec![
            Span::styled(" ✓ ", Style::default().fg(C_GREEN).add_modifier(Modifier::BOLD)),
            Span::styled(format!("Completed  {}", completed), Style::default().fg(C_FG)),
        ]),
        Line::from(vec![
            Span::styled(" ⟳ ", Style::default().fg(C_YELLOW).add_modifier(Modifier::BOLD)),
            Span::styled(format!("Running    {}", running), Style::default().fg(C_FG)),
        ]),
        Line::from(vec![
            Span::styled(" ○ ", Style::default().fg(C_DIM).add_modifier(Modifier::BOLD)),
            Span::styled(format!("Pending    {}", pending), Style::default().fg(C_FG)),
        ]),
        Line::from(vec![
            Span::styled(" ✗ ", Style::default().fg(C_RED).add_modifier(Modifier::BOLD)),
            Span::styled(format!("Failed     {}", failed), Style::default().fg(C_FG)),
        ]),
    ];

    let para = Paragraph::new(Text::from(lines)).style(Style::default());
    f.render_widget(para, inner);
}

fn render_sidebar_legend(f: &mut Frame, area: Rect, app: &App) {
    let block = bordered(" Legend ".into(), C_ACCENT);
    let inner = block.inner(area);
    f.render_widget(block, area);

    let findings = app.get_findings();
    let mut counts = std::collections::HashMap::new();
    for f in &findings {
        *counts.entry(f.severity.clone()).or_insert(0) += 1;
    }

    let sevs = [Severity::Critical, Severity::High, Severity::Medium, Severity::Low, Severity::Info];
    let mut lines = Vec::new();
    for sev in &sevs {
        let count = counts.get(sev).copied().unwrap_or(0);
        let c = severity_color(sev);
        lines.push(Line::from(vec![
            Span::styled(" ■ ", Style::default().fg(c)),
            Span::styled(
                format!("{:8}  {}", format!("{}", sev), count),
                Style::default().fg(c),
            ),
        ]));
    }

    let para = Paragraph::new(Text::from(lines)).style(Style::default());
    f.render_widget(para, inner);
}

// ── Setup Panel ─────────────────────────────────────────────
fn render_setup_panel(f: &mut Frame, area: Rect, app: &App) {
    let block = bordered(" Scan Setup ".into(), C_ACCENT);
    let inner = block.inner(area);
    f.render_widget(block, area);

    let mut lines = Vec::new();

    lines.push(Line::from(vec![
        Span::styled(" ⚡ ", Style::default().fg(C_YELLOW)),
        Span::styled("Configure Target & Mode", Style::default().fg(C_FG).add_modifier(Modifier::BOLD)),
        Span::styled("  (Tab/↑↓ to navigate, Enter to start)", Style::default().fg(C_DIM)),
    ]));
    lines.push(Line::from(""));

    // ── Target Input ──
    let target_active = app.setup_field == SetupField::Target;
    lines.push(Line::from(vec![
        Span::styled(" ┌─ ", Style::default().fg(if target_active { C_ACCENT } else { C_DIM })),
        Span::styled("Target", Style::default().fg(if target_active { C_ACCENT } else { C_DIM }).add_modifier(Modifier::BOLD)),
        Span::styled(" ─────────────────────────────────────────┐", Style::default().fg(if target_active { C_ACCENT } else { C_DIM })),
    ]));

    let target_style = if target_active {
        Style::default().fg(C_FG).bg(Color::DarkGray)
    } else {
        Style::default().fg(C_FG)
    };
    let placeholder = if app.target_input.is_empty() {
        " Enter IP, domain, or CIDR (e.g., 10.10.10.10, scanme.nmap.org, 10.0.0.0/24)".to_string()
    } else {
        app.target_input.clone()
    };
    lines.push(Line::from(vec![
        Span::styled(" │ ", Style::default().fg(if target_active { C_ACCENT } else { C_DIM })),
        Span::styled(placeholder, target_style),
        Span::styled(if target_active { "█" } else { " " }, Style::default().fg(C_ACCENT)),
        Span::styled(" │", Style::default().fg(if target_active { C_ACCENT } else { C_DIM })),
    ]));

    // Validation hint
    if !app.target_input.is_empty() && app.target_input.trim().len() >= 3 {
        lines.push(Line::from(vec![
            Span::styled(" │ ", Style::default().fg(if target_active { C_ACCENT } else { C_DIM })),
            Span::styled(" ✓ Valid input", Style::default().fg(C_GREEN)),
            Span::styled("  │", Style::default().fg(if target_active { C_ACCENT } else { C_DIM })),
        ]));
    } else if !app.target_input.is_empty() {
        lines.push(Line::from(vec![
            Span::styled(" │ ", Style::default().fg(if target_active { C_ACCENT } else { C_DIM })),
            Span::styled(" ○ Type a valid target", Style::default().fg(C_YELLOW)),
            Span::styled("  │", Style::default().fg(if target_active { C_ACCENT } else { C_DIM })),
        ]));
    }

    lines.push(Line::from(vec![
        Span::styled(" └────────────────────────────────────────────┘", Style::default().fg(if target_active { C_ACCENT } else { C_DIM })),
    ]));
    lines.push(Line::from(""));

    // ── Mode Selector ──
    let mode_active = app.setup_field == SetupField::Mode;
    lines.push(Line::from(vec![
        Span::styled(" ┌─ ", Style::default().fg(if mode_active { C_ACCENT } else { C_DIM })),
        Span::styled("Scan Mode", Style::default().fg(if mode_active { C_ACCENT } else { C_DIM }).add_modifier(Modifier::BOLD)),
        Span::styled(" ────────────────────────────────────────┐", Style::default().fg(if mode_active { C_ACCENT } else { C_DIM })),
    ]));

    let modes = WorkflowMode::all();
    for (i, mode) in modes.iter().enumerate() {
        let is_sel = i == app.selected_mode_index;
        let is_active = app.setup_field == SetupField::Mode;
        let (mc, mn, _) = mode_style(*mode);
        let sel_marker = if is_sel { "●" } else { "○" };
        let style = if is_sel && is_active {
            Style::default().fg(Color::Black).bg(mc)
        } else if is_sel {
            Style::default().fg(mc).add_modifier(Modifier::BOLD)
        } else if is_active {
            Style::default().fg(C_DIM).bg(Color::DarkGray)
        } else {
            Style::default().fg(C_DIM)
        };
        let arrow = if is_sel { "▸" } else { " " };
        lines.push(Line::from(vec![
            Span::styled(" │ ", Style::default().fg(if mode_active { C_ACCENT } else { C_DIM })),
            Span::styled(format!("{} {} ", arrow, sel_marker), Style::default().fg(if is_sel { mc } else { C_DIM })),
            Span::styled(format!("{:14}", mn), style),
            Span::styled(format!(" {}", mode.description()), Style::default().fg(if is_sel { C_FG } else { C_DIM })),
        ]));
    }
    lines.push(Line::from(vec![
        Span::styled(" └────────────────────────────────────────────┘", Style::default().fg(if mode_active { C_ACCENT } else { C_DIM })),
    ]));
    lines.push(Line::from(""));

    // ── Flags ──
    let flag_defs = [
        ("Docker", SetupField::Docker, app.docker_enabled, "Kali Linux container tools (nmap, ffuf, hydra)"),
        ("Stealth", SetupField::Stealth, app.stealth_enabled, "Random jitter, no banners, low concurrency"),
        ("NoReport", SetupField::NoReport, app.no_report_enabled, "Skip report generation after scan"),
    ];

    let flags_active = [SetupField::Docker, SetupField::Stealth, SetupField::NoReport].contains(&app.setup_field);
    lines.push(Line::from(vec![
        Span::styled(" ┌─ ", Style::default().fg(if flags_active { C_ACCENT } else { C_DIM })),
        Span::styled("Options", Style::default().fg(if flags_active { C_ACCENT } else { C_DIM }).add_modifier(Modifier::BOLD)),
        Span::styled(" ──────────────────────────────────────────┐", Style::default().fg(if flags_active { C_ACCENT } else { C_DIM })),
    ]));

    for (name, field, enabled, desc) in &flag_defs {
        let is_active = app.setup_field == *field;
        let checkbox = if *enabled { "☑" } else { "☐" };
        let fg = if *enabled { C_GREEN } else { C_DIM };
        let style = if is_active {
            Style::default().fg(Color::Black).bg(if *enabled { C_GREEN } else { C_DIM })
        } else {
            Style::default().fg(fg)
        };
        lines.push(Line::from(vec![
            Span::styled(" │ ", Style::default().fg(if is_active { C_ACCENT } else { C_DIM })),
            Span::styled(format!(" {} {}", checkbox, name), style),
            Span::styled(format!("  {}", desc), Style::default().fg(C_DIM)),
        ]));
    }
    lines.push(Line::from(vec![
        Span::styled(" └────────────────────────────────────────────┘", Style::default().fg(if flags_active { C_ACCENT } else { C_DIM })),
    ]));
    lines.push(Line::from(""));

    // ── Start Button ──
    let start_active = app.setup_field == SetupField::Start;
    let can_start = !app.target_input.trim().is_empty();
    let start_style = if start_active {
        Style::default().fg(Color::Black).bg(if can_start { C_GREEN } else { C_DIM })
    } else if can_start {
        Style::default().fg(C_GREEN).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(C_DIM)
    };

    let btn_text = if can_start {
        format!(" ▶ LAUNCH SCAN — {}  ", app.target_input.trim())
    } else {
        " ▶ START SCAN  (set target first)  ".to_string()
    };

    lines.push(Line::from(vec![
        Span::styled(" ", Style::default().fg(C_DIM)),
        Span::styled(btn_text, start_style),
    ]));

    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled(" [Tab/Shift+Tab] Navigate  ", Style::default().fg(C_DIM)),
        Span::styled("[↑/↓] Change mode  ", Style::default().fg(C_DIM)),
        Span::styled("[Space] Toggle  ", Style::default().fg(C_DIM)),
        Span::styled("[Enter] Start", Style::default().fg(if can_start { C_GREEN } else { C_DIM })),
    ]));

    let para = Paragraph::new(Text::from(lines)).style(Style::default());
    f.render_widget(para, inner);
}

// ── Status panel ─────────────────────────────────────────────
fn render_status_panel(f: &mut Frame, area: Rect, app: &App) {
    let block = bordered(" Overview ".into(), C_ACCENT);
    let inner = block.inner(area);
    f.render_widget(block, area);

    let (pending, running, completed, failed) = app.task_counts();
    let total = pending + running + completed + failed;
    let pct = if total > 0 { completed as f64 / total as f64 } else { 0.0 };

    let findings = app.get_findings();
    let paths = app.get_attack_paths();
    let counts = findings.iter().fold([0usize; 5], |mut acc, f| {
        let idx = match f.severity {
            Severity::Critical => 4,
            Severity::High => 3,
            Severity::Medium => 2,
            Severity::Low => 1,
            Severity::Info => 0,
        };
        acc[idx] += 1;
        acc
    });

    let mut lines = vec![
        Line::from(vec![
            Span::styled("Target:  ", Style::default().fg(C_DIM)),
            Span::styled(&app.target, Style::default().fg(C_FG).add_modifier(Modifier::BOLD)),
        ]),
        Line::from(vec![
            Span::styled("Mode:    ", Style::default().fg(C_DIM)),
            Span::styled(format!("{}", app.mode), Style::default().fg(C_ACCENT).add_modifier(Modifier::BOLD)),
        ]),
        Line::from(vec![
            Span::styled("Elapsed: ", Style::default().fg(C_DIM)),
            Span::styled(app.elapsed_str(), Style::default().fg(C_ACCENT)),
        ]),
        Line::from(""),
        Line::from(Span::styled("── Severity Breakdown ──", Style::default().fg(C_DIM))),
    ];

    let max_count = *counts.iter().max().unwrap_or(&1).max(&1);
    let sev_labels = [Severity::Info, Severity::Low, Severity::Medium, Severity::High, Severity::Critical];
    for sev in &sev_labels {
        let idx = match *sev {
            Severity::Info => 0, Severity::Low => 1, Severity::Medium => 2,
            Severity::High => 3, Severity::Critical => 4,
        };
        let c = counts[idx];
        let color = severity_color(sev);
        let bar_w = if max_count > 0 { (c as f64 / max_count as f64 * 10.0).round() as usize } else { 0 };
        let bar = "█".repeat(bar_w);
        lines.push(Line::from(vec![
            Span::styled(format!(" {:>8} ", format!("{}", sev)), Style::default().fg(color).add_modifier(Modifier::BOLD)),
            Span::styled(format!("{:>3} ", c), Style::default().fg(color)),
            Span::styled(bar, Style::default().fg(color)),
        ]));
    }

    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled("── Progress ──", Style::default().fg(C_DIM))));

    let progress_pct = (pct * 100.0) as u32;
    let bar_w = 20usize;
    let filled = (pct * bar_w as f64).round() as usize;
    let empty = bar_w.saturating_sub(filled);
    let progress_bar = format!("[{}{}] {}%", "█".repeat(filled), "░".repeat(empty), progress_pct);

    let progress_color = match progress_pct {
        100 => C_GREEN,
        50..=99 => C_YELLOW,
        _ => C_ACCENT,
    };
    lines.push(Line::from(vec![
        Span::styled(" ", Style::default().fg(C_DIM)),
        Span::styled(progress_bar, Style::default().fg(progress_color)),
        Span::styled(format!("  {} tasks done", completed), Style::default().fg(C_DIM)),
    ]));
    if running > 0 {
        lines.push(Line::from(vec![
            Span::styled(" ", Style::default().fg(C_DIM)),
            Span::styled(format!("⟳ {} running", running), Style::default().fg(C_YELLOW)),
        ]));
    }
    if pending > 0 {
        lines.push(Line::from(vec![
            Span::styled(" ", Style::default().fg(C_DIM)),
            Span::styled(format!("○ {} pending", pending), Style::default().fg(C_DIM)),
        ]));
    }
    if failed > 0 {
        lines.push(Line::from(vec![
            Span::styled(" ", Style::default().fg(C_DIM)),
            Span::styled(format!("✗ {} failed", failed), Style::default().fg(C_RED)),
        ]));
    }

    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled("── Results ──", Style::default().fg(C_DIM))));
    lines.push(Line::from(vec![
        Span::styled(format!("  {:>3}  ", findings.len()), Style::default().fg(C_ACCENT).add_modifier(Modifier::BOLD)),
        Span::styled("findings total", Style::default().fg(C_FG)),
    ]));
    lines.push(Line::from(vec![
        Span::styled(format!("  {:>3}  ", paths.len()), Style::default().fg(C_ACCENT2).add_modifier(Modifier::BOLD)),
        Span::styled("attack paths", Style::default().fg(C_FG)),
    ]));

    if !findings.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled("── Latest Findings ──", Style::default().fg(C_DIM))));
        for finding in findings.iter().rev().take(4) {
            let sev_color = severity_color(&finding.severity);
            lines.push(Line::from(vec![
                Span::styled(" ■ ", Style::default().fg(sev_color)),
                Span::styled(&finding.title, Style::default().fg(C_FG)),
            ]));
        }
    }

    let para = Paragraph::new(Text::from(lines))
        .style(Style::default())
        .scroll((app.scroll_offset as u16, 0));
    f.render_widget(para, inner);
}

fn render_findings_panel(f: &mut Frame, area: Rect, app: &App) {
    let block = bordered(format!(" Findings ({})", app.get_findings().len()), C_ACCENT);
    let inner = block.inner(area);
    f.render_widget(block, area);

    // Filter bar (top row)
    let filter_names: Vec<Line> = FindingFilter::all().iter().map(|filter| {
        let is_active = *filter == app.finding_filter;
        let label = format!(" {} ", filter.name());
        if is_active {
            Line::from(Span::styled(label, Style::default().fg(Color::Black).bg(C_ACCENT).add_modifier(Modifier::BOLD)))
        } else {
            Line::from(Span::styled(label, Style::default().fg(C_DIM)))
        }
    }).collect();

    let filter_line = Line::from({
        let mut spans = vec![Span::styled(" [f] ", Style::default().fg(C_DIM))];
        for (i, filter_name) in filter_names.iter().enumerate() {
            if i > 0 {
                spans.push(Span::styled("│", Style::default().fg(C_DIM)));
            }
            if let Some(span) = filter_name.spans.first() {
                spans.push(span.clone());
            }
        }
        spans
    });

    let filter_height = 1;

    // Findings list
    let findings = app.get_filtered_findings();
    let mut sorted: Vec<(usize, &Finding)> = findings.iter().enumerate().collect();
    sorted.sort_by(|a, b| {
        let sev_order = |s: &Severity| -> u8 {
            match s {
                Severity::Critical => 0,
                Severity::High => 1,
                Severity::Medium => 2,
                Severity::Low => 3,
                Severity::Info => 4,
            }
        };
        let a_sev = sev_order(&a.1.severity);
        let b_sev = sev_order(&b.1.severity);
        a_sev.cmp(&b_sev)
    });

    let items: Vec<ListItem> = sorted.iter().map(|(orig_idx, finding)| {
        let sev_color = severity_color(&finding.severity);
        let is_selected = app.selected_finding == Some(*orig_idx);
        let prefix = if is_selected { "▸" } else { " " };

        let content = Line::from(vec![
            Span::styled(format!("{} ", prefix), Style::default().fg(C_YELLOW)),
            Span::styled(
                format!("{:8}", format!("{}", finding.severity)),
                Style::default().fg(sev_color).add_modifier(Modifier::BOLD),
            ),
            Span::raw(" "),
            Span::styled(
                finding.title.clone(),
                if is_selected {
                    Style::default().fg(Color::Black).bg(C_ACCENT)
                } else {
                    Style::default().fg(C_FG)
                },
            ),
        ]);

        ListItem::new(content)
    }).collect();

    // Render: filter bar + list
    let filter_rect = Rect::new(inner.x, inner.y, inner.width, filter_height);
    let list_rect = Rect::new(inner.x, inner.y + filter_height, inner.width, inner.height.saturating_sub(filter_height));

    let filter_para = Paragraph::new(Text::from(vec![filter_line])).style(Style::default());
    f.render_widget(filter_para, filter_rect);

    if items.is_empty() {
        let msg = if findings.is_empty() && !app.get_findings().is_empty() {
            format!(" No {} findings match filter.", app.finding_filter.name().to_lowercase())
        } else {
            " No findings yet. Run a scan.".to_string()
        };
        let empty = List::new(vec![ListItem::new(Line::from(Span::styled(msg, Style::default().fg(C_DIM))))]);
        f.render_widget(empty, list_rect);
    } else {
        let list = List::new(items);
        f.render_widget(list, list_rect);
    }
}

fn render_attack_paths_panel(f: &mut Frame, area: Rect, app: &App) {
    let block = bordered(format!(" Attack Paths ({})", app.get_attack_paths().len()), C_ACCENT);
    let inner = block.inner(area);
    f.render_widget(block, area);

    let paths = app.get_attack_paths();
    let mut lines = Vec::new();

    if paths.is_empty() {
        lines.push(Line::from(Span::styled(
            " No attack paths identified yet.",
            Style::default().fg(C_DIM),
        )));
    } else {
        for (i, path) in paths.iter().enumerate() {
            let is_selected = app.selected_path == Some(i);
            let prefix = if is_selected { "▸" } else { " " };
            let impact_color = severity_color(&path.impact);

            let header_style = if is_selected {
                Style::default().fg(Color::Black).bg(C_ACCENT).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(C_FG).add_modifier(Modifier::BOLD)
            };

            // Visual likelihood bar
            let bar_width = 15u16;
            let filled = (path.likelihood * bar_width as f32).round() as u16;
            let empty = bar_width.saturating_sub(filled);
            let bar_color = if path.likelihood >= 0.8 { C_GREEN }
                else if path.likelihood >= 0.5 { C_YELLOW }
                else { C_DIM };
            let bar: String = format!(
                "[{}{}] {:3.0}%",
                "█".repeat(filled as usize),
                "░".repeat(empty as usize),
                path.likelihood * 100.0,
            );

            lines.push(Line::from(vec![
                Span::styled(format!("{} ", prefix), Style::default().fg(C_YELLOW)),
                Span::styled(format!("{}. ", i + 1), header_style),
                Span::styled(path.name.clone(), header_style),
                Span::raw(" "),
                Span::styled(
                    format!("[{}]", path.impact),
                    Style::default().fg(impact_color).add_modifier(Modifier::BOLD),
                ),
            ]));

            lines.push(Line::from(vec![
                Span::raw("    "),
                Span::styled(bar, Style::default().fg(bar_color)),
            ]));

            lines.push(Line::from(Span::styled(
                format!("    {}", path.description),
                Style::default().fg(C_DIM),
            )));

            // Steps
            for step in &path.steps {
                lines.push(Line::from(Span::styled(
                    format!("    ├─ {} [{}]", step.description, step.technique),
                    Style::default().fg(C_DIM),
                )));
            }
            lines.push(Line::from(""));
        }
    }

    let para = Paragraph::new(Text::from(lines))
        .style(Style::default())
        .scroll((app.scroll_offset as u16, 0));
    f.render_widget(para, inner);
}

fn render_workflow_panel(f: &mut Frame, area: Rect, app: &App) {
    let block = bordered(" Workflow Plan ".into(), C_ACCENT);
    let inner = block.inner(area);
    f.render_widget(block, area);

    let mut lines = Vec::new();

    if let Some(plan) = app.get_plan() {
        lines.push(Line::from(vec![
            Span::styled(plan.name.clone(), Style::default().fg(C_FG).add_modifier(Modifier::BOLD)),
            Span::styled(format!(" ({})", plan.estimated_time), Style::default().fg(C_DIM)),
        ]));
        lines.push(Line::from(Span::styled(
            plan.description.clone(),
            Style::default().fg(C_DIM),
        )));
        lines.push(Line::from(""));

        let summary = app.status_summary();
        for step in &plan.steps {
            let status = summary.iter().find(|(name, _)| {
                name.to_lowercase().contains(&step.module)
            });

            let (icon, icon_color) = match status {
                Some((_, TaskStatus::Completed)) => ("✓", C_GREEN),
                Some((_, TaskStatus::Running)) => ("⟳", C_YELLOW),
                Some((_, TaskStatus::Failed)) => ("✗", C_RED),
                _ => ("○", C_DIM),
            };

            let dep_str = if step.depends_on.is_empty() {
                "".to_string()
            } else {
                let min = step.depends_on.iter().min().unwrap_or(&0);
                format!(" [after step {}]", min)
            };

            lines.push(Line::from(vec![
                Span::styled(format!(" {} ", icon), Style::default().fg(icon_color).add_modifier(Modifier::BOLD)),
                Span::styled(
                    format!("{:20}", step.module),
                    Style::default().fg(C_ACCENT),
                ),
                Span::raw(" "),
                Span::styled(step.description.clone(), Style::default().fg(C_FG)),
                Span::styled(dep_str, Style::default().fg(C_DIM)),
            ]));
        }
    } else {
        lines.push(Line::from(Span::styled(
            " No workflow plan generated yet.",
            Style::default().fg(C_DIM),
        )));
    }

    let para = Paragraph::new(Text::from(lines))
        .style(Style::default())
        .scroll((app.scroll_offset as u16, 0));
    f.render_widget(para, inner);
}

fn render_education_panel(f: &mut Frame, area: Rect, app: &App) {
    let block = bordered(" Education ".into(), C_ACCENT);
    let inner = block.inner(area);
    f.render_widget(block, area);

    let mut lines = Vec::new();

    let is_minimal = matches!(app.mode, WorkflowMode::Professional | WorkflowMode::Quick | WorkflowMode::Stealth);

    if is_minimal {
        let msg = match app.mode {
            WorkflowMode::Professional => "Professional mode: educational explanations minimized.",
            WorkflowMode::Quick => "Quick mode: educational explanations minimized.",
            WorkflowMode::Stealth => "Stealth mode: educational explanations minimized.",
            _ => "",
        };
        lines.push(Line::from(Span::styled(msg, Style::default().fg(C_DIM))));
    } else if let Some(idx) = app.selected_finding {
        let mut edu_parts: Vec<(String, String)> = Vec::new();
        if let Some(finding) = app.educational_for_finding(idx) {
            if let Some(ref edu) = finding.education {
                edu_parts.push(("What is this?".into(), edu.what.clone()));
                edu_parts.push(("Why it matters".into(), edu.why.clone()));
                edu_parts.push(("How it was discovered".into(), edu.how.clone()));
                edu_parts.push(("Mitigation".into(), edu.mitigation.clone()));
                for r in &edu.references {
                    edu_parts.push(("References".into(), r.clone()));
                }
            }
        }

        let mut first_ref = true;
        for (header, content) in edu_parts.iter() {
            if content.is_empty() { continue; }
            match header.as_str() {
                "References" => {
                    if first_ref {
                        lines.push(Line::from(Span::styled(
                            "\nReferences:",
                            Style::default().fg(C_ACCENT).add_modifier(Modifier::BOLD),
                        )));
                        first_ref = false;
                    }
                    lines.push(Line::from(Span::styled(
                        format!("  • {}", content),
                        Style::default().fg(C_FG),
                    )));
                }
                _ => {
                    lines.push(Line::from(Span::styled(
                        format!("\n{}:", header),
                        Style::default().fg(C_ACCENT).add_modifier(Modifier::BOLD),
                    )));
                    lines.push(Line::from(Span::styled(
                        content.clone(),
                        Style::default().fg(C_FG),
                    )));
                }
            }
        }
    }

    if lines.is_empty() {
        lines.push(Line::from(Span::styled(
            " Select a finding in the Findings tab (↑↓, Enter) to see explanations.",
            Style::default().fg(C_DIM),
        )));
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(" Each finding includes:", Style::default().fg(C_ACCENT).add_modifier(Modifier::BOLD))));
        for item in &["What is this?", "Why it matters", "How it was discovered", "Mitigation advice", "References"] {
            lines.push(Line::from(Span::styled(
                format!("  • {}", item),
                Style::default().fg(C_FG),
            )));
        }
    }

    let para = Paragraph::new(Text::from(lines))
        .style(Style::default())
        .scroll((app.scroll_offset as u16, 0));
    f.render_widget(para, inner);
}

fn render_log_panel(f: &mut Frame, area: Rect, app: &App) {
    let block = bordered(" Live Output ".into(), C_ACCENT);
    let inner = block.inner(area);
    f.render_widget(block, area);

    let logs = app.logs.lock().unwrap();
    let visible: Vec<&String> = logs.iter().rev().take(inner.height as usize).collect();
    let lines: Vec<Line> = visible.iter().rev().map(|log| {
        let (tag, color) = if log.contains("[CHAIN]")               { ("CHAIN", C_LMAG) }
        else if log.contains("[Port Scanner]")                      { ("SCAN", C_YELLOW) }
        else if log.contains("[DNS")                                { ("DNS", C_ACCENT) }
        else if log.contains("[Web Enum]")                          { ("WEB", C_GREEN) }
        else if log.contains("[SMB]")                               { ("SMB", C_LMAG) }
        else if log.contains("[OSINT]")                             { ("OSINT", C_LBLUE) }
        else if log.contains("[Cred")                               { ("CRED", C_LRED) }
        else if log.contains("[Exploit")                            { ("EXPL", C_YELLOW) }
        else if log.contains("[PrivEsc")                            { ("PE", C_LMAG) }
        else if log.contains("[NetworkDiscovery]")                  { ("NET", C_ACCENT2) }
        else if log.contains("Finding:")                            { ("FIND", C_RED) }
        else if log.contains("Complete") || log.contains("complete") || log.contains("[DONE]")
                                                                     { ("DONE", C_GREEN) }
        else if log.contains("[ERROR]") || log.contains("failed")   { ("ERR", C_RED) }
        else                                                        { ("INFO", C_ACCENT) };

        Line::from(vec![
            Span::styled(format!(" {:>5} ", tag), Style::default().fg(color).add_modifier(Modifier::BOLD).bg(Color::Black)),
            Span::styled(" ", Style::default().fg(C_DIM)),
            Span::styled(log.as_str(), Style::default().fg(C_FG)),
        ])
    }).collect();

    let para = Paragraph::new(Text::from(lines)).style(Style::default());
    f.render_widget(para, inner);
}

fn render_status_bar(f: &mut Frame, area: Rect, app: &App) {
    let (pending, running, completed, failed) = app.task_counts();
    let total = pending + running + completed + failed;
    let findings_count = app.get_findings().len();
    let paths_count = app.get_attack_paths().len();

    let status = if app.phase == AppPhase::Config {
        "Configure your scan".into()
    } else if total > 0 {
        if running > 0 {
            format!("Running {} tasks...", running)
        } else if completed == total {
            "All tasks complete ✓".into()
        } else {
            format!("{} tasks pending", pending)
        }
    } else {
        "Initializing...".into()
    };

    let vpn_tag = if app.has_vpn() {
        let vpn_s = app.vpn_status_str();
        if vpn_s.contains("Connected") {
            "VPN│".to_string()
        } else if vpn_s.contains("err") || vpn_s.contains("off") {
            String::new()
        } else {
            "VPN│".to_string()
        }
    } else {
        String::new()
    };
    let docker_tag = if app.has_docker() {
        "Docker│".to_string()
    } else {
        String::new()
    };

    let bar = Paragraph::new(Line::from(vec![
        Span::styled(" ", Style::default().fg(C_DIM)),
        Span::styled("Status:", Style::default().fg(C_DIM)),
        Span::raw(" "),
        Span::styled(&status, Style::default().fg(if running > 0 { C_YELLOW } else if completed == total && total > 0 { C_GREEN } else { C_DIM })),
        Span::styled("  │  ", Style::default().fg(C_DIM)),
        Span::styled(format!("Tasks: {}/{}", completed, total), Style::default().fg(if completed == total && total > 0 { C_GREEN } else { C_ACCENT })),
        Span::styled("  │  ", Style::default().fg(C_DIM)),
        Span::styled(format!("Findings: {}", findings_count), Style::default().fg(C_ACCENT2)),
        Span::styled("  │  ", Style::default().fg(C_DIM)),
        Span::styled(format!("Paths: {}", paths_count), Style::default().fg(C_LRED)),
        Span::styled("  │  ", Style::default().fg(C_DIM)),
        Span::styled(vpn_tag, Style::default().fg(C_GREEN)),
        Span::styled(docker_tag, Style::default().fg(C_YELLOW)),
        Span::styled(app.elapsed_str(), Style::default().fg(C_DIM)),
        Span::styled("  ", Style::default().fg(C_DIM)),
        Span::styled(" [?] Help │ [q] Quit", Style::default().fg(C_DIM)),
    ]))
    .style(Style::default().bg(Color::Black))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(C_DIM)),
    );
    f.render_widget(bar, area);
}

fn render_help_overlay(f: &mut Frame, area: Rect) {
    let overlay = Rect::new(
        (area.width.saturating_sub(64)) / 2,
        (area.height.saturating_sub(28)) / 2,
        64.min(area.width),
        28.min(area.height),
    );

    f.render_widget(Clear, overlay);

    let help_lines = vec![
        Line::from(Span::styled(" Sentinel Help", Style::default().fg(C_ACCENT).add_modifier(Modifier::BOLD))),
        Line::from(""),
        Line::from(Span::styled(" ── Scan Screen ──", Style::default().fg(C_GREEN))),
        Line::from("  Tab / Shift+Tab   Next / Previous tab"),
        Line::from("  1-6, S            Jump to tab (number or S for Setup)"),
        Line::from("  ↑ / ↓             Scroll content up/down"),
        Line::from("  Enter             Select finding → Education tab"),
        Line::from("  f                 Cycle finding severity filter"),
        Line::from("  ?                 Toggle this help overlay"),
        Line::from("  q / Esc           Quit Sentinel"),
        Line::from(""),
        Line::from(Span::styled(" ── Tabs ──", Style::default().fg(C_GREEN))),
        Line::from("  S Setup      Configure & launch a scan"),
        Line::from("  1 Status     Overview, progress, severity breakdown"),
        Line::from("  2 Findings   Discovered vulnerabilities (filterable)"),
        Line::from("  3 Paths      Attack path analysis & likelihood"),
        Line::from("  4 Workflow   Scan plan & task execution status"),
        Line::from("  5 Education  Detailed explanations for each finding"),
        Line::from("  6 Log        Live module output feed"),
        Line::from(""),
        Line::from(Span::styled(" ── Scan Modes ──", Style::default().fg(C_GREEN))),
        Line::from("  Beginner     Verbose, educational, all modules"),
        Line::from("  Professional Concise output, minimal explanations"),
        Line::from("  CTF          Aggressive: ~6500 ports, flag hunting, OSINT"),
        Line::from("  Quick        Fast: 31 common ports only"),
        Line::from("  Stealth      Evasion: jitter, no banners, low concurrency"),
        Line::from("  Recon-Only   DNS recon + port scan only"),
        Line::from("  Full         Maximum aggressiveness, all modules"),
        Line::from(""),
        Line::from(Span::styled(" Press any key to close.", Style::default().fg(C_DIM))),
    ];

    let block = Block::default()
        .title(" Help ")
        .borders(Borders::ALL)
        .border_type(BorderType::Thick)
        .border_style(Style::default().fg(C_ACCENT))
        .style(Style::default().bg(Color::Black));
    let para = Paragraph::new(Text::from(help_lines)).block(block).style(Style::default());
    f.render_widget(para, overlay);
}

fn render_content(f: &mut Frame, area: Rect, app: &App) {
    match app.active_tab {
        Tab::Setup => render_setup_panel(f, area, app),
        Tab::Status => render_status_panel(f, area, app),
        Tab::Findings => render_findings_panel(f, area, app),
        Tab::AttackPaths => render_attack_paths_panel(f, area, app),
        Tab::Workflow => render_workflow_panel(f, area, app),
        Tab::Education => render_education_panel(f, area, app),
        Tab::Log => render_log_panel(f, area, app),
    }
}

// ── Main render entry point ──────────────────────────────────
pub fn render_ui(f: &mut Frame, app: &App) {
    let area = f.area();
    if area.width < 60 || area.height < 20 {
        f.render_widget(
            Paragraph::new("Terminal too small — resize to at least 60×20")
                .style(Style::default().fg(C_RED)),
            area,
        );
        return;
    }

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),  // header
            Constraint::Length(2),  // tabs
            Constraint::Min(5),     // body
            Constraint::Length(1),  // status bar
        ])
        .split(area);

    render_header(f, chunks[0], app);
    render_tab_bar(f, chunks[1], app);

    if app.phase == AppPhase::Config {
        // Setup mode: full width for setup panel, no sidebar
        render_content(f, chunks[2], app);
    } else {
        // Normal mode: sidebar + content
        let body_chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(22), Constraint::Percentage(78)])
            .split(chunks[2]);

        render_sidebar(f, body_chunks[0], app);
        render_content(f, body_chunks[1], app);
    }

    render_status_bar(f, chunks[3], app);

    if app.show_help {
        render_help_overlay(f, area);
    }
}
