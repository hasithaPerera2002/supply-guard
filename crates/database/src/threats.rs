use chrono::{DateTime, Utc};
use rusqlite::{params, Connection, Result as SqlResult};
use shared::{Severity, ThreatResult, ThreatType};
use std::path::PathBuf;
use std::sync::Mutex;
use tracing::{debug, error, info};

pub struct ThreatDatabase {
    conn: Mutex<Connection>,
}

impl ThreatDatabase {
    pub fn new(db_path: &std::path::Path) -> SqlResult<Self> {
        // Create parent directory if it doesn't exist
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| rusqlite::Error::InvalidPath(db_path.to_path_buf()))?;
        }

        let conn = Connection::open(db_path)?;
        let db = Self {
            conn: Mutex::new(conn),
        };
        db.init_schema()?;
        Ok(db)
    }

    fn init_schema(&self) -> SqlResult<()> {
        let conn = self.conn.lock().unwrap();
        
        conn.execute(
            "CREATE TABLE IF NOT EXISTS scanned_files (
                path TEXT PRIMARY KEY,
                hash TEXT NOT NULL,
                last_scanned INTEGER NOT NULL,
                is_clean BOOLEAN NOT NULL
            )",
            [],
        )?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS threats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_path TEXT NOT NULL,
                threat_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                matched_pattern TEXT NOT NULL,
                pattern_name TEXT NOT NULL,
                context TEXT,
                remediation TEXT,
                timestamp INTEGER NOT NULL,
                resolved BOOLEAN DEFAULT FALSE
            )",
            [],
        )?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS quarantined (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                original_path TEXT NOT NULL,
                quarantine_path TEXT NOT NULL,
                threat_id INTEGER,
                timestamp INTEGER NOT NULL,
                FOREIGN KEY (threat_id) REFERENCES threats(id)
            )",
            [],
        )?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS whitelist (
                path_pattern TEXT PRIMARY KEY,
                reason TEXT,
                added_at INTEGER NOT NULL
            )",
            [],
        )?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_threats_timestamp ON threats(timestamp)",
            [],
        )?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_scanned_files_hash ON scanned_files(hash)",
            [],
        )?;

        Ok(())
    }

    pub fn record_threat(&self, threat: &ThreatResult) -> SqlResult<i64> {
        let conn = self.conn.lock().unwrap();
        
        conn.execute(
            "INSERT INTO threats (file_path, threat_type, severity, matched_pattern, pattern_name, context, remediation, timestamp, resolved)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                threat.file_path.to_string_lossy(),
                format!("{:?}", threat.threat_type),
                threat.severity.as_str(),
                threat.matched_pattern,
                threat.pattern_name,
                threat.context,
                threat.remediation,
                threat.timestamp.timestamp(),
                false
            ],
        )?;

        let id = conn.last_insert_rowid();
        info!("Recorded threat #{}: {} in {}", id, threat.threat_type.as_str(), threat.file_path.display());
        Ok(id)
    }

    pub fn get_recent_threats(&self, limit: i32) -> SqlResult<Vec<ThreatResult>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, file_path, threat_type, severity, matched_pattern, pattern_name, context, remediation, timestamp
             FROM threats
             WHERE resolved = FALSE
             ORDER BY timestamp DESC
             LIMIT ?1"
        )?;

        let rows = stmt.query_map(params![limit], |row| {
            let file_path: String = row.get(1)?;
            let threat_type_str: String = row.get(2)?;
            let severity_str: String = row.get(3)?;
            let timestamp: i64 = row.get(8)?;

            let threat_type = match threat_type_str.as_str() {
                "VscodeAutoRun" => ThreatType::VscodeAutoRun,
                "GitHookMalware" => ThreatType::GitHookMalware,
                "MaliciousInstallScript" => ThreatType::MaliciousInstallScript,
                "ReverseShell" => ThreatType::ReverseShell,
                "CredentialTheft" => ThreatType::CredentialTheft,
                "ObfuscatedCode" => ThreatType::ObfuscatedCode,
                "SuspiciousNetwork" => ThreatType::SuspiciousNetwork,
                "DependencyConfusion" => ThreatType::DependencyConfusion,
                "BuildScriptAttack" => ThreatType::BuildScriptAttack,
                "CiCdBackdoor" => ThreatType::CiCdBackdoor,
                _ => ThreatType::MaliciousInstallScript,
            };

            let severity = Severity::from_str(&severity_str).unwrap_or(Severity::Medium);

            Ok(ThreatResult {
                file_path: PathBuf::from(file_path),
                threat_type,
                severity,
                line_number: None,
                matched_pattern: row.get(4)?,
                pattern_name: row.get(5)?,
                context: row.get(6)?,
                remediation: row.get(7)?,
                timestamp: DateTime::from_timestamp(timestamp, 0).unwrap_or_else(Utc::now),
            })
        })?;

        let mut threats = Vec::new();
        for row in rows {
            threats.push(row?);
        }
        Ok(threats)
    }

    pub fn mark_resolved(&self, threat_id: i64) -> SqlResult<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE threats SET resolved = TRUE WHERE id = ?1",
            params![threat_id],
        )?;
        Ok(())
    }

    pub fn quarantine_file(&self, original_path: &PathBuf, quarantine_path: &PathBuf, threat_id: Option<i64>) -> SqlResult<i64> {
        let conn = self.conn.lock().unwrap();
        
        conn.execute(
            "INSERT INTO quarantined (original_path, quarantine_path, threat_id, timestamp)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                original_path.to_string_lossy(),
                quarantine_path.to_string_lossy(),
                threat_id,
                Utc::now().timestamp()
            ],
        )?;

        Ok(conn.last_insert_rowid())
    }

    pub fn get_quarantined(&self) -> SqlResult<Vec<(i64, PathBuf, PathBuf, Option<i64>)>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, original_path, quarantine_path, threat_id FROM quarantined ORDER BY timestamp DESC"
        )?;

        let rows = stmt.query_map([], |row| {
            Ok((
                row.get(0)?,
                PathBuf::from(row.get::<_, String>(1)?),
                PathBuf::from(row.get::<_, String>(2)?),
                row.get(3)?,
            ))
        })?;

        let mut results = Vec::new();
        for row in rows {
            results.push(row?);
        }
        Ok(results)
    }

    pub fn add_whitelist(&self, pattern: &str, reason: Option<&str>) -> SqlResult<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO whitelist (path_pattern, reason, added_at)
             VALUES (?1, ?2, ?3)",
            params![pattern, reason, Utc::now().timestamp()],
        )?;
        Ok(())
    }

    pub fn is_whitelisted(&self, path: &PathBuf) -> SqlResult<bool> {
        let conn = self.conn.lock().unwrap();
        let path_str = path.to_string_lossy();
        
        let mut stmt = conn.prepare("SELECT COUNT(*) FROM whitelist WHERE ?1 LIKE path_pattern")?;
        let count: i32 = stmt.query_row(params![path_str], |row| row.get(0))?;
        
        Ok(count > 0)
    }

    pub fn get_statistics(&self) -> SqlResult<(i32, i32, i32)> {
        let conn = self.conn.lock().unwrap();
        
        let total: i32 = conn.query_row(
            "SELECT COUNT(*) FROM threats",
            [],
            |row| row.get(0),
        )?;

        let unresolved: i32 = conn.query_row(
            "SELECT COUNT(*) FROM threats WHERE resolved = FALSE",
            [],
            |row| row.get(0),
        )?;

        let quarantined: i32 = conn.query_row(
            "SELECT COUNT(*) FROM quarantined",
            [],
            |row| row.get(0),
        )?;

        Ok((total, unresolved, quarantined))
    }
}
