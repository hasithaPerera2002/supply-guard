CREATE TABLE IF NOT EXISTS scanned_files (
    path TEXT PRIMARY KEY,
    hash TEXT NOT NULL,
    last_scanned INTEGER NOT NULL,
    is_clean BOOLEAN NOT NULL
);

CREATE TABLE IF NOT EXISTS threats (
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
);

CREATE TABLE IF NOT EXISTS quarantined (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    original_path TEXT NOT NULL,
    quarantine_path TEXT NOT NULL,
    threat_id INTEGER,
    timestamp INTEGER NOT NULL,
    FOREIGN KEY (threat_id) REFERENCES threats(id)
);

CREATE TABLE IF NOT EXISTS whitelist (
    path_pattern TEXT PRIMARY KEY,
    reason TEXT,
    added_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_threats_timestamp ON threats(timestamp);
CREATE INDEX IF NOT EXISTS idx_scanned_files_hash ON scanned_files(hash);
