use async_trait::async_trait;
use tokio::sync::mpsc::Sender;
use crate::core::adaptive::{Intent, ScanContext};
use crate::core::findings::Finding;
use crate::core::workflow::WorkflowMode;
use std::sync::{Arc, Mutex};

#[async_trait]
pub trait Module: Send + Sync {
    fn name(&self) -> &str;
    async fn execute_with_ports(&self, target: &str, open_ports: &[u16], mode: &WorkflowMode, tx: Sender<String>) -> Result<Vec<Finding>, anyhow::Error>;

    /// Adaptive entry point used by the orchestration engine.
    ///
    /// The default implementation ignores the [`Intent`] and [`ScanContext`] and
    /// simply delegates to [`Module::execute_with_ports`], so every existing
    /// module keeps its current behaviour unchanged. Modules that participate in
    /// chains (`creds`, `web`) override this to read prior discoveries from the
    /// shared context and act on a specific intent.
    async fn execute_adaptive(
        &self,
        target: &str,
        open_ports: &[u16],
        mode: &WorkflowMode,
        intent: &Intent,
        ctx: Arc<Mutex<ScanContext>>,
        tx: Sender<String>,
    ) -> Result<Vec<Finding>, anyhow::Error> {
        let _ = (intent, ctx);
        self.execute_with_ports(target, open_ports, mode, tx).await
    }
}

pub struct ModuleRegistry {
    modules: Vec<(&'static str, Arc<dyn Module>)>,
}

impl ModuleRegistry {
    pub fn new() -> Self {
        Self { modules: Vec::new() }
    }

    pub fn register(&mut self, name: &'static str, module: Arc<dyn Module>) {
        self.modules.push((name, module));
    }

    pub fn get(&self, name: &str) -> Option<&Arc<dyn Module>> {
        self.modules.iter().find(|(n, _)| *n == name).map(|(_, m)| m)
    }

    pub fn all(&self) -> &[(&'static str, Arc<dyn Module>)] {
        &self.modules
    }

    pub fn build_default() -> Self {
        let mut registry = Self::new();
        registry.register("recon", Arc::new(recon::DnsRecon));
        registry.register("port_scan", Arc::new(port_scanner::PortScanner));
        registry.register("web", Arc::new(web::WebEnum));
        registry.register("smb", Arc::new(smb::SmbEnum));
        registry.register("creds", Arc::new(creds::CredChecker));
        registry.register("exploit", Arc::new(exploit::ExploitHunter));
        registry.register("priv_esc", Arc::new(priv_esc::PrivEsc));
        registry.register("osint", Arc::new(osint::OsintModule));
        registry.register("network_discovery", Arc::new(network_discovery::NetworkDiscovery));
        registry
    }
}

pub mod port_scanner;
pub mod recon;
pub mod web;
pub mod smb;
pub mod creds;
pub mod exploit;
pub mod priv_esc;
pub mod osint;
pub mod network_discovery;
