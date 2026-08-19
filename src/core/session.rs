#![allow(dead_code)]
use crate::core::findings::{AttackPath, Finding, FindingStore};
use anyhow::{Context, Result};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sqlx::sqlite::{SqlitePool, SqlitePoolOptions};
use sqlx::Row;

const DB_PATH: &str = "sentinel_history.db";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionRecord {
    pub id: i64,
    pub target: String,
    pub mode: String,
    pub started_at: String,
    pub completed_at: String,
    pub total_findings: i32,
    pub critical_count: i32,
    pub high_count: i32,
    pub medium_count: i32,
    pub low_count: i32,
    pub info_count: i32,
    pub attack_paths: i32,
}

pub struct SessionDb {
    pool: SqlitePool,
}

impl SessionDb {
    pub async fn new() -> Result<Self> {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect(&format!("sqlite:{}?mode=rwc", DB_PATH))
            .await
            .with_context(|| format!("Failed to open session database: {}", DB_PATH))?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                mode TEXT NOT NULL,
                started_at TEXT NOT NULL,
                completed_at TEXT NOT NULL,
                total_findings INTEGER DEFAULT 0,
                critical_count INTEGER DEFAULT 0,
                high_count INTEGER DEFAULT 0,
                medium_count INTEGER DEFAULT 0,
                low_count INTEGER DEFAULT 0,
                info_count INTEGER DEFAULT 0,
                attack_paths INTEGER DEFAULT 0,
                data TEXT NOT NULL
            )",
        )
        .execute(&pool)
        .await?;

        Ok(Self { pool })
    }

    pub async fn save(&self, target: &str, mode: &str, store: &FindingStore) -> Result<i64> {
        let started_at = Utc::now().to_rfc3339();
        let completed_at = Utc::now().to_rfc3339();

        let mut critical = 0i32;
        let mut high = 0i32;
        let mut medium = 0i32;
        let mut low = 0i32;
        let mut info = 0i32;
        for f in &store.findings {
            match f.severity {
                crate::core::findings::Severity::Critical => critical += 1,
                crate::core::findings::Severity::High => high += 1,
                crate::core::findings::Severity::Medium => medium += 1,
                crate::core::findings::Severity::Low => low += 1,
                crate::core::findings::Severity::Info => info += 1,
            }
        }

        #[derive(Serialize)]
        struct SessionData {
            findings: Vec<Finding>,
            attack_paths: Vec<AttackPath>,
        }

        let data = serde_json::to_string(&SessionData {
            findings: store.findings.clone(),
            attack_paths: store.attack_paths.clone(),
        })?;

        let result = sqlx::query(
            "INSERT INTO sessions (target, mode, started_at, completed_at, total_findings, \
             critical_count, high_count, medium_count, low_count, info_count, attack_paths, data) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(target)
        .bind(mode)
        .bind(&started_at)
        .bind(&completed_at)
        .bind(store.findings.len() as i32)
        .bind(critical)
        .bind(high)
        .bind(medium)
        .bind(low)
        .bind(info)
        .bind(store.attack_paths.len() as i32)
        .bind(&data)
        .execute(&self.pool)
        .await?;

        Ok(result.last_insert_rowid())
    }

    pub async fn list(&self) -> Result<Vec<SessionRecord>> {
        let rows = sqlx::query(
            "SELECT id, target, mode, started_at, completed_at, total_findings, \
             critical_count, high_count, medium_count, low_count, info_count, attack_paths \
             FROM sessions ORDER BY id DESC LIMIT 50",
        )
        .fetch_all(&self.pool)
        .await?;

        let records = rows
            .iter()
            .map(|r| SessionRecord {
                id: r.get("id"),
                target: r.get("target"),
                mode: r.get("mode"),
                started_at: r.get("started_at"),
                completed_at: r.get("completed_at"),
                total_findings: r.get("total_findings"),
                critical_count: r.get("critical_count"),
                high_count: r.get("high_count"),
                medium_count: r.get("medium_count"),
                low_count: r.get("low_count"),
                info_count: r.get("info_count"),
                attack_paths: r.get("attack_paths"),
            })
            .collect();

        Ok(records)
    }

    pub async fn load(&self, id: i64) -> Result<Option<(String, String, FindingStore)>> {
        let row = sqlx::query("SELECT target, mode, data FROM sessions WHERE id = ?")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;

        match row {
            Some(r) => {
                let target: String = r.get("target");
                let mode: String = r.get("mode");
                let data: String = r.get("data");
                #[derive(Deserialize)]
                struct SessionData {
                    findings: Vec<Finding>,
                    attack_paths: Vec<AttackPath>,
                }
                let sd: SessionData = serde_json::from_str(&data)?;
                let mut store = FindingStore::new();
                for f in sd.findings {
                    store.add(f);
                }
                for p in sd.attack_paths {
                    store.add_path(p);
                }
                Ok(Some((target, mode, store)))
            }
            None => Ok(None),
        }
    }
}
