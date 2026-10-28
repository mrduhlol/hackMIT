CREATE TABLE targets (id TEXT PRIMARY KEY, url TEXT NOT NULL UNIQUE, authorized_at TEXT NOT NULL);
CREATE TABLE scans (id TEXT PRIMARY KEY, target_id TEXT REFERENCES targets(id), test_id TEXT NOT NULL, status TEXT NOT NULL, started_at TEXT NOT NULL, ended_at TEXT, result TEXT, progress INTEGER NOT NULL DEFAULT 0);
CREATE INDEX scan_history ON scans(started_at DESC);
CREATE UNIQUE INDEX one_active_scan ON scans((1)) WHERE status='RUNNING';
CREATE TABLE events (id INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT NOT NULL DEFAULT(strftime('%Y-%m-%dT%H:%M:%fZ','now')), action TEXT NOT NULL, resource TEXT NOT NULL);
CREATE TABLE controls (id INTEGER PRIMARY KEY CHECK(id=1), stopped INTEGER NOT NULL DEFAULT 0);
INSERT INTO controls(id) VALUES(1);
