use rusqlite::{params, Connection, Result as SqlResult};
use std::path::PathBuf;
use std::sync::Mutex;
use tracing::debug;

pub struct CacheDatabase {
    conn: Mutex<Connection>,
}

impl CacheDatabase {
    pub fn new(db_path: &std::path::Path) -> SqlResult<Self> {
        // Create parent directory if it doesn't exist
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|_| rusqlite::Error::InvalidPath(db_path.to_path_buf()))?;
        }

        let conn = Connection::open(db_path)?;
        let cache = Self {
            conn: Mutex::new(conn),
        };
        cache.init_schema()?;
        Ok(cache)
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
            "CREATE INDEX IF NOT EXISTS idx_scanned_files_hash ON scanned_files(hash)",
            [],
        )?;

        Ok(())
    }

    pub fn get_hash(&self, path: &PathBuf) -> SqlResult<Option<String>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT hash FROM scanned_files WHERE path = ?1")?;
        
        match stmt.query_row(params![path.to_string_lossy()], |row| row.get(0)) {
            Ok(hash) => Ok(Some(hash)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub fn update_hash(&self, path: &PathBuf, hash: &str, is_clean: bool) -> SqlResult<()> {
        let conn = self.conn.lock().unwrap();
        
        conn.execute(
            "INSERT OR REPLACE INTO scanned_files (path, hash, last_scanned, is_clean)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                path.to_string_lossy(),
                hash,
                chrono::Utc::now().timestamp(),
                is_clean
            ],
        )?;

        debug!("Updated cache for {}", path.display());
        Ok(())
    }

    pub fn clear(&self) -> SqlResult<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM scanned_files", [])?;
        Ok(())
    }
}
