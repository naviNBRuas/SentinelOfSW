//! Adaptive orchestration engine.
//!
//! Sentinel's "smart" layer is deterministic and fully auditable — there is no
//! AI and no black box here. Instead, a small set of **trigger rules** inspect
//! the live [`FindingStore`] and a shared [`ScanContext`] blackboard after the
//! static workflow plan has run, and schedule bounded **follow-up** module runs
//! that were never in the original plan. Every scheduling decision carries a
//! human-readable rationale that is logged to the user.
//!
//! Two real chains ship in v1:
//!
//! * **Credential reuse** — a credential proven on one service (a default
//!   credential, or one leaked in an exposed file) is validated against every
//!   other auth-capable service on the target.
//! * **Web secret harvest** — an exposed `.env` / `.git/config` is fetched and
//!   parsed for credentials, which are fed back into the pool and re-trigger
//!   credential reuse (a depth-2 chain).
//!
//! Termination is guaranteed by [`AdaptiveEngine::max_rounds`], a global
//! follow-up cap, and a per-trigger dedup set in [`ScanContext`].

use crate::core::findings::FindingStore;
use crate::modules::creds::service_from_port;
use std::collections::HashSet;

/// A credential discovered during a scan, with provenance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credential {
    pub service: String,
    /// Port where the credential was proven, or `0` if harvested from a file.
    pub port: u16,
    pub user: String,
    pub pass: String,
    /// Where it came from, e.g. `"default-creds@21"` or `".env@http://host:80"`.
    pub source: String,
}

/// What a follow-up module run should do. `Standard` reproduces the module's
/// normal behaviour; the others carry the payload a chain needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Intent {
    Standard,
    CredReuse { credentials: Vec<Credential> },
    SecretHarvest { urls: Vec<String> },
}

/// A scheduled follow-up: which module to run, with what intent, and why.
#[derive(Debug, Clone)]
pub struct FollowUp {
    pub module: String,
    pub intent: Intent,
    pub rationale: String,
}

/// Shared blackboard that chained modules read from and write to. Wrapped in an
/// `Arc<Mutex<_>>` by the scanner so modules can mutate it across rounds.
#[derive(Debug, Default)]
pub struct ScanContext {
    pub credentials: Vec<Credential>,
    /// Notable exposed-file URLs/paths recorded for reporting.
    pub loot: Vec<String>,
    triggered: HashSet<String>,
}

impl ScanContext {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a credential, ignoring exact duplicates (same user/pass/service/port).
    pub fn add_credential(&mut self, cred: Credential) {
        if !self.credentials.iter().any(|c| {
            c.user == cred.user && c.pass == cred.pass && c.service == cred.service && c.port == cred.port
        }) {
            self.credentials.push(cred);
        }
    }

    /// Record that a trigger fired. Returns `true` the first time a given key is
    /// seen and `false` afterwards — the core dedup guard that bounds the loop.
    pub fn record_trigger(&mut self, key: &str) -> bool {
        self.triggered.insert(key.to_string())
    }

    /// A stable signature of the current credential set, used so that adding a
    /// *new* credential (e.g. a leaked one) re-arms the cred-reuse rule while an
    /// unchanged set stays deduped.
    fn credential_signature(&self) -> String {
        let mut tags: Vec<String> = self
            .credentials
            .iter()
            .map(|c| format!("{}:{}", c.user, c.pass))
            .collect();
        tags.sort();
        tags.dedup();
        tags.join("|")
    }
}

/// Ports that accept credentials and that the `creds` module knows how to test.
pub fn is_auth_capable(port: u16) -> bool {
    service_from_port(port) != "Unknown"
}

/// The deterministic rule engine. Holds only its safety caps.
#[derive(Debug, Clone)]
pub struct AdaptiveEngine {
    pub max_rounds: usize,
    pub max_followups: usize,
}

impl Default for AdaptiveEngine {
    fn default() -> Self {
        Self { max_rounds: 3, max_followups: 32 }
    }
}

impl AdaptiveEngine {
    /// Evaluate every rule against the current state and return the deduped,
    /// not-yet-fired follow-ups (recording their trigger keys so they never fire
    /// twice). Respects the global `max_followups` cap.
    pub fn evaluate(
        &self,
        store: &FindingStore,
        ctx: &mut ScanContext,
        open_ports: &[u16],
    ) -> Vec<FollowUp> {
        let mut out = Vec::new();
        self.rule_cred_reuse(ctx, open_ports, &mut out);
        self.rule_secret_harvest(store, ctx, &mut out);
        out.truncate(self.max_followups);
        out
    }

    /// R1 — validate known credentials across every auth-capable open port.
    fn rule_cred_reuse(&self, ctx: &mut ScanContext, open_ports: &[u16], out: &mut Vec<FollowUp>) {
        if ctx.credentials.is_empty() {
            return;
        }
        if !open_ports.iter().any(|&p| is_auth_capable(p)) {
            return;
        }
        let key = format!("credreuse:{}", ctx.credential_signature());
        if !ctx.record_trigger(&key) {
            return;
        }
        let credentials = ctx.credentials.clone();
        let n = credentials.len();
        out.push(FollowUp {
            module: "creds".into(),
            intent: Intent::CredReuse { credentials },
            rationale: format!(
                "{} discovered credential(s) → validating reuse across all auth-capable services",
                n
            ),
        });
    }

    /// R2 — fetch & parse exposed `.env` / `.git/config` flagged by the web module.
    fn rule_secret_harvest(&self, store: &FindingStore, ctx: &mut ScanContext, out: &mut Vec<FollowUp>) {
        let mut urls = Vec::new();
        for f in store.by_module("web") {
            // Match on the exposed path itself, not severity: the web module
            // tags `.env` differently across its dir-brute and CTF code paths,
            // so keying off severity would be brittle. Info-level noise (e.g.
            // robots.txt) never matches the secret-path patterns below.
            if !is_secret_path_title(&f.title) {
                continue;
            }
            if let Some(url) = harvest_url_from_evidence(&f.evidence) {
                let key = format!("harvest:{}", url);
                if ctx.record_trigger(&key) {
                    urls.push(url);
                }
            }
        }
        if !urls.is_empty() {
            let rationale = format!("exposed source/config files detected → harvesting {} URL(s) for secrets", urls.len());
            out.push(FollowUp {
                module: "web".into(),
                intent: Intent::SecretHarvest { urls },
                rationale,
            });
        }
    }
}

/// Does a web finding title name an exposed secret-bearing path?
fn is_secret_path_title(title: &str) -> bool {
    let t = title.to_ascii_lowercase();
    t.contains(".env") || t.contains(".git/config") || t.contains(".git/head") || t.contains(".git")
}

/// Reconstruct the harvestable URL from a web finding's evidence line, which has
/// the form `GET <base>/<path> returned HTTP <status>`.
fn harvest_url_from_evidence(evidence: &[String]) -> Option<String> {
    for line in evidence {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("GET ") {
            if let Some(url) = rest.split_whitespace().next() {
                if url.starts_with("http") {
                    return Some(url.to_string());
                }
            }
        }
    }
    None
}

/// Parse a `.env` body for credential-looking `KEY=VALUE` pairs. Pairs whose key
/// looks like a username are paired with the nearest password-looking value.
pub fn parse_env_secrets(body: &str) -> Vec<(String, String, String)> {
    // Returns (key, user, pass) triples; user may be empty if only a secret value.
    let mut user: Option<String> = None;
    let mut out = Vec::new();
    for raw in body.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line);
        let Some((key, val)) = line.split_once('=') else { continue };
        let key = key.trim().trim_matches('"');
        let val = val.trim().trim_matches('"').trim_matches('\'');
        if val.is_empty() {
            continue;
        }
        let ku = key.to_ascii_uppercase();
        if ku.contains("USER") || ku.contains("LOGIN") || ku.ends_with("_UID") {
            user = Some(val.to_string());
        } else if ku.contains("PASS") || ku.contains("PWD") || ku.contains("SECRET") || ku.contains("TOKEN") || ku.contains("KEY") {
            out.push((key.to_string(), user.clone().unwrap_or_default(), val.to_string()));
        }
    }
    out
}

/// Parse a `.git/config` body for credentials embedded in remote URLs, i.e.
/// `https://user:pass@host/repo.git`.
pub fn parse_git_config_creds(body: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for raw in body.lines() {
        let line = raw.trim();
        if !line.starts_with("url") {
            continue;
        }
        let Some(idx) = line.find("://") else { continue };
        let after = &line[idx + 3..];
        let Some(at) = after.find('@') else { continue };
        let creds = &after[..at];
        if let Some((user, pass)) = creds.split_once(':') {
            if !user.is_empty() && !pass.is_empty() {
                out.push((user.to_string(), pass.to_string()));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::findings::{Finding, Severity};

    fn cred(user: &str, pass: &str, service: &str, port: u16) -> Credential {
        Credential { service: service.into(), port, user: user.into(), pass: pass.into(), source: "test".into() }
    }

    #[test]
    fn test_record_trigger_dedup() {
        let mut ctx = ScanContext::new();
        assert!(ctx.record_trigger("k"));
        assert!(!ctx.record_trigger("k"));
        assert!(ctx.record_trigger("other"));
    }

    #[test]
    fn test_add_credential_dedups_exact() {
        let mut ctx = ScanContext::new();
        ctx.add_credential(cred("root", "toor", "SSH", 22));
        ctx.add_credential(cred("root", "toor", "SSH", 22));
        assert_eq!(ctx.credentials.len(), 1);
        ctx.add_credential(cred("root", "toor", "FTP", 21));
        assert_eq!(ctx.credentials.len(), 2);
    }

    #[test]
    fn test_is_auth_capable() {
        assert!(is_auth_capable(22));
        assert!(is_auth_capable(3306));
        assert!(!is_auth_capable(53));
        assert!(!is_auth_capable(9999));
    }

    #[test]
    fn test_evaluate_empty_state_no_followups() {
        let engine = AdaptiveEngine::default();
        let store = FindingStore::new();
        let mut ctx = ScanContext::new();
        assert!(engine.evaluate(&store, &mut ctx, &[22, 80]).is_empty());
    }

    #[test]
    fn test_cred_reuse_fires_once_then_dedups() {
        let engine = AdaptiveEngine::default();
        let store = FindingStore::new();
        let mut ctx = ScanContext::new();
        ctx.add_credential(cred("root", "toor", "FTP", 21));

        let first = engine.evaluate(&store, &mut ctx, &[21, 22, 3306]);
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].module, "creds");
        assert!(matches!(first[0].intent, Intent::CredReuse { .. }));

        // Same credential set → deduped.
        let second = engine.evaluate(&store, &mut ctx, &[21, 22, 3306]);
        assert!(second.is_empty());
    }

    #[test]
    fn test_cred_reuse_rearms_on_new_credential() {
        let engine = AdaptiveEngine::default();
        let store = FindingStore::new();
        let mut ctx = ScanContext::new();
        ctx.add_credential(cred("root", "toor", "FTP", 21));
        assert_eq!(engine.evaluate(&store, &mut ctx, &[21, 22]).len(), 1);

        // A newly leaked credential changes the signature → rule re-arms.
        ctx.add_credential(cred("admin", "s3cret", "", 0));
        let again = engine.evaluate(&store, &mut ctx, &[21, 22]);
        assert_eq!(again.len(), 1);
    }

    #[test]
    fn test_cred_reuse_skipped_without_auth_ports() {
        let engine = AdaptiveEngine::default();
        let store = FindingStore::new();
        let mut ctx = ScanContext::new();
        ctx.add_credential(cred("root", "toor", "FTP", 21));
        // Only non-auth ports open.
        assert!(engine.evaluate(&store, &mut ctx, &[53, 123]).is_empty());
    }

    #[test]
    fn test_secret_harvest_fires_on_exposed_env() {
        let engine = AdaptiveEngine::default();
        let mut store = FindingStore::new();
        store.add(
            Finding::new("t", "web", "Discovered Path: /.env", "exposed", Severity::High)
                .with_evidence(vec!["GET http://t:80/.env returned HTTP 200".into()]),
        );
        let mut ctx = ScanContext::new();
        let fu = engine.evaluate(&store, &mut ctx, &[]);
        assert_eq!(fu.len(), 1);
        assert_eq!(fu[0].module, "web");
        match &fu[0].intent {
            Intent::SecretHarvest { urls } => assert_eq!(urls, &vec!["http://t:80/.env".to_string()]),
            _ => panic!("expected SecretHarvest"),
        }
        // Deduped on repeat.
        assert!(engine.evaluate(&store, &mut ctx, &[]).is_empty());
    }

    #[test]
    fn test_secret_harvest_ignores_low_severity_and_other_paths() {
        let engine = AdaptiveEngine::default();
        let mut store = FindingStore::new();
        store.add(
            Finding::new("t", "web", "Discovered Path: /images", "", Severity::Low)
                .with_evidence(vec!["GET http://t:80/images returned HTTP 200".into()]),
        );
        let mut ctx = ScanContext::new();
        assert!(engine.evaluate(&store, &mut ctx, &[]).is_empty());
    }

    #[test]
    fn test_max_followups_cap() {
        let engine = AdaptiveEngine { max_rounds: 3, max_followups: 1 };
        let mut store = FindingStore::new();
        store.add(
            Finding::new("t", "web", "Discovered Path: /.env", "", Severity::High)
                .with_evidence(vec!["GET http://t:80/.env returned HTTP 200".into()]),
        );
        let mut ctx = ScanContext::new();
        ctx.add_credential(cred("root", "toor", "FTP", 21));
        // Both rules want to fire, but the cap clamps to one.
        let fu = engine.evaluate(&store, &mut ctx, &[21, 22]);
        assert_eq!(fu.len(), 1);
    }

    #[test]
    fn test_harvest_url_from_evidence() {
        assert_eq!(
            harvest_url_from_evidence(&["GET http://h:8080/.git/config returned HTTP 200".into()]),
            Some("http://h:8080/.git/config".to_string())
        );
        assert_eq!(harvest_url_from_evidence(&["no url here".into()]), None);
    }

    #[test]
    fn test_parse_env_secrets() {
        let body = "# comment\nDB_USER=admin\nDB_PASSWORD=hunter2\nexport API_TOKEN=\"abc123\"\nEMPTY=\nPORT=5432\n";
        let got = parse_env_secrets(body);
        // DB_PASSWORD paired with DB_USER; API_TOKEN as a standalone secret.
        assert!(got.iter().any(|(k, u, p)| k == "DB_PASSWORD" && u == "admin" && p == "hunter2"));
        assert!(got.iter().any(|(k, _, p)| k == "API_TOKEN" && p == "abc123"));
        // PORT is not a secret; EMPTY has no value.
        assert!(!got.iter().any(|(k, _, _)| k == "PORT" || k == "EMPTY"));
    }

    #[test]
    fn test_parse_git_config_creds() {
        let body = "[remote \"origin\"]\n    url = https://deploy:t0 pS3cret@github.com/acme/app.git\n".replace(" ", "");
        let got = parse_git_config_creds(&body);
        assert_eq!(got, vec![("deploy".to_string(), "t0pS3cret".to_string())]);
        assert!(parse_git_config_creds("url = https://github.com/acme/app.git").is_empty());
    }
}
