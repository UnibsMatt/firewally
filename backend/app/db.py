"""SQLite persistence for networks, services, rules, settings and apply history."""
import json
import os
import sqlite3
from contextlib import contextmanager

from .models import SettingsIn

DB_PATH = os.environ.get("DB_PATH", "/data/firewall.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS networks (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL UNIQUE,
    cidr        TEXT,
    interface   TEXT,
    description TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS services (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL UNIQUE,
    protocol    TEXT NOT NULL,
    ports       TEXT NOT NULL DEFAULT '',
    description TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS rules (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    position       INTEGER NOT NULL,
    name           TEXT NOT NULL,
    chain          TEXT NOT NULL,
    src_network_id INTEGER REFERENCES networks(id) ON DELETE RESTRICT,
    dst_network_id INTEGER REFERENCES networks(id) ON DELETE RESTRICT,
    service_id     INTEGER REFERENCES services(id) ON DELETE RESTRICT,
    action         TEXT NOT NULL,
    log            INTEGER NOT NULL DEFAULT 0,
    enabled        INTEGER NOT NULL DEFAULT 1,
    comment        TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS history (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    ts      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    user    TEXT NOT NULL,
    status  TEXT NOT NULL,
    message TEXT NOT NULL DEFAULT '',
    script  TEXT NOT NULL
);
"""

DEFAULT_SERVICES = [
    ("SSH", "tcp", "22", "Secure shell"),
    ("HTTP", "tcp", "80", "Web"),
    ("HTTPS", "tcp", "443", "Web (TLS)"),
    ("Web", "tcp", "80,443", "HTTP + HTTPS"),
    ("DNS", "tcp+udp", "53", "Name resolution"),
    ("NTP", "udp", "123", "Time sync"),
    ("ICMP", "icmp", "", "Ping / ICMP"),
]


@contextmanager
def connect():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db() -> None:
    os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)
    with connect() as c:
        c.execute("PRAGMA journal_mode = WAL")
        c.executescript(SCHEMA)
        if c.execute("SELECT COUNT(*) FROM services").fetchone()[0] == 0:
            c.executemany(
                "INSERT INTO services (name, protocol, ports, description) VALUES (?, ?, ?, ?)",
                DEFAULT_SERVICES,
            )
        # In-memory confirmation timers do not survive a restart: the previous
        # ruleset is re-applied on startup, so pending changes are rolled back.
        c.execute(
            "UPDATE history SET status = 'rolled_back', "
            "message = 'Container restarted before confirmation' WHERE status = 'pending'"
        )


def row(r: sqlite3.Row) -> dict:
    d = dict(r)
    for key in ("log", "enabled"):
        if key in d:
            d[key] = bool(d[key])
    return d


def get_settings(c: sqlite3.Connection) -> dict:
    settings = SettingsIn().model_dump()
    for r in c.execute("SELECT key, value FROM settings"):
        if r["key"] in settings:
            settings[r["key"]] = json.loads(r["value"])
    return settings


def save_settings(c: sqlite3.Connection, settings: dict) -> None:
    c.executemany(
        "INSERT INTO settings (key, value) VALUES (?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        [(k, json.dumps(v)) for k, v in settings.items()],
    )


def add_history(user: str, status: str, message: str, script: str) -> int:
    with connect() as c:
        cur = c.execute(
            "INSERT INTO history (user, status, message, script) VALUES (?, ?, ?, ?)",
            (user, status, message, script),
        )
        return cur.lastrowid


def set_history_status(history_id: int, status: str, message: str) -> None:
    with connect() as c:
        c.execute("UPDATE history SET status = ?, message = ? WHERE id = ?", (status, message, history_id))


def last_applied_script() -> str | None:
    with connect() as c:
        r = c.execute("SELECT script FROM history WHERE status = 'applied' ORDER BY id DESC LIMIT 1").fetchone()
        return r["script"] if r else None
