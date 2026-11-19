"""SQLite persistence: schema, connections, transactions and the audit chain.

Design notes
------------
* One database file holds both operational state and the append-only ledger.
* Every mutation runs inside ``BEGIN IMMEDIATE`` so writers serialise on the
  database write lock; readers keep running under WAL.
* Each ledger row chains to the previous one by hash, so truncation, reorder or
  in-place edit of history is detectable without trusting the writer.
* Read-only views open the file with ``mode=ro``; SQLite then refuses writes at
  the engine level, not merely by convention.
"""

from __future__ import annotations

import os
import sqlite3
import time
from contextlib import contextmanager
from typing import Any, Iterator

from .errors import GateError
from .util import canonical_json, digest_of, sha256_text

GENESIS_HASH = "sha256:" + "0" * 64

SCHEMA_SQL = """
PRAGMA user_version = 1;

CREATE TABLE IF NOT EXISTS meta (
    k TEXT PRIMARY KEY,
    v TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ledger (
    seq          INTEGER PRIMARY KEY,
    ts           TEXT NOT NULL,
    kind         TEXT NOT NULL,
    subject      TEXT NOT NULL,
    payload      TEXT NOT NULL,
    payload_hash TEXT NOT NULL,
    prev_hash    TEXT NOT NULL,
    entry_hash   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tenant (
    tenant_id      TEXT PRIMARY KEY,
    environments   TEXT NOT NULL,
    version_policy TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS app (
    app_id    TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    name      TEXT
);

CREATE TABLE IF NOT EXISTS software (
    tenant_id      TEXT NOT NULL,
    name           TEXT NOT NULL,
    version        TEXT NOT NULL,
    content_digest TEXT NOT NULL,
    published_at   TEXT NOT NULL,
    allowed_envs   TEXT,
    superseded     INTEGER NOT NULL DEFAULT 0,
    revoked_at     TEXT,
    updated_seq    INTEGER NOT NULL,
    PRIMARY KEY (tenant_id, name, version)
);

CREATE TABLE IF NOT EXISTS software_dep (
    tenant_id   TEXT NOT NULL,
    name        TEXT NOT NULL,
    version     TEXT NOT NULL,
    dep_name    TEXT NOT NULL,
    constraint_json TEXT NOT NULL,
    PRIMARY KEY (tenant_id, name, version, dep_name)
);

CREATE TABLE IF NOT EXISTS app_version (
    app_id      TEXT NOT NULL,
    version     TEXT NOT NULL,
    tenant_id   TEXT NOT NULL,
    deps_json   TEXT NOT NULL,
    covered     TEXT,
    updated_seq INTEGER NOT NULL,
    PRIMARY KEY (app_id, version)
);

CREATE TABLE IF NOT EXISTS role_registry (
    tenant_id TEXT NOT NULL,
    role      TEXT NOT NULL,
    PRIMARY KEY (tenant_id, role)
);

CREATE TABLE IF NOT EXISTS person_role (
    person_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    role      TEXT NOT NULL,
    PRIMARY KEY (person_id, tenant_id, role)
);

CREATE TABLE IF NOT EXISTS reviewer_duty (
    reviewer_id  TEXT PRIMARY KEY,
    tenant_id    TEXT NOT NULL,
    person_id    TEXT NOT NULL,
    role         TEXT NOT NULL,
    duty_epoch   INTEGER NOT NULL,
    duty_version INTEGER NOT NULL,
    active_from  TEXT NOT NULL,
    active_to    TEXT,
    revoked_at   TEXT,
    updated_seq  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS software_digest_history (
    tenant_id      TEXT NOT NULL,
    name           TEXT NOT NULL,
    version        TEXT NOT NULL,
    content_digest TEXT NOT NULL,
    epoch          INTEGER NOT NULL,
    seen_at        TEXT NOT NULL,
    retired_at     TEXT,
    PRIMARY KEY (tenant_id, name, version, epoch)
);

CREATE TABLE IF NOT EXISTS app_fingerprint_history (
    tenant_id   TEXT NOT NULL,
    app_id      TEXT NOT NULL,
    environment TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    first_seq   INTEGER NOT NULL,
    last_seq    INTEGER NOT NULL,
    retired_seq INTEGER,
    PRIMARY KEY (tenant_id, app_id, environment, fingerprint)
);

CREATE TABLE IF NOT EXISTS signature (
    signature_id TEXT PRIMARY KEY,
    reviewer_id  TEXT NOT NULL,
    tenant_id    TEXT NOT NULL,
    status       TEXT NOT NULL,
    signed_at    TEXT NOT NULL,
    subject      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS risk (
    risk_id         TEXT PRIMARY KEY,
    tenant_id       TEXT NOT NULL,
    app_id          TEXT NOT NULL,
    dep_name        TEXT NOT NULL,
    dep_version     TEXT NOT NULL,
    content_digest  TEXT NOT NULL,
    severity        TEXT NOT NULL,
    status          TEXT NOT NULL,
    registered_at   TEXT NOT NULL,
    updated_seq     INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS risk_event (
    risk_id TEXT NOT NULL,
    seq     INTEGER NOT NULL,
    kind    TEXT NOT NULL,
    payload TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS fix_signal (
    fix_id          TEXT PRIMARY KEY,
    risk_id         TEXT NOT NULL,
    evidence_version TEXT NOT NULL,
    content_digest  TEXT NOT NULL,
    fixed_at        TEXT NOT NULL,
    verified        INTEGER NOT NULL,
    seq             INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS waiver (
    waiver_id       TEXT PRIMARY KEY,
    risk_id         TEXT NOT NULL,
    tenant_id       TEXT NOT NULL,
    app_id          TEXT NOT NULL,
    content_digest  TEXT NOT NULL,
    environment     TEXT NOT NULL,
    evidence_version TEXT NOT NULL,
    repair_deadline TEXT NOT NULL,
    requested_by    TEXT NOT NULL,
    status          TEXT NOT NULL,
    created_at      TEXT NOT NULL,
    updated_seq     INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS waiver_event (
    waiver_id TEXT NOT NULL,
    seq       INTEGER NOT NULL,
    kind      TEXT NOT NULL,
    payload   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS approval (
    approval_id       TEXT PRIMARY KEY,
    waiver_id         TEXT NOT NULL,
    reviewer_id       TEXT NOT NULL,
    role              TEXT NOT NULL,
    signature_id      TEXT NOT NULL,
    decision          TEXT NOT NULL,
    app_id            TEXT NOT NULL,
    app_version       TEXT NOT NULL,
    environment       TEXT NOT NULL,
    risk_id           TEXT NOT NULL,
    content_digest    TEXT NOT NULL,
    evidence_version  TEXT NOT NULL,
    severity_snapshot TEXT NOT NULL,
    deadline_snapshot TEXT NOT NULL,
    duty_epoch        INTEGER NOT NULL,
    duty_version      INTEGER NOT NULL,
    signed_at         TEXT NOT NULL,
    status            TEXT NOT NULL,
    revoked_reason    TEXT,
    seq               INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS approval_event (
    approval_id TEXT NOT NULL,
    seq         INTEGER NOT NULL,
    kind        TEXT NOT NULL,
    payload     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS release (
    tenant_id    TEXT NOT NULL,
    app_id       TEXT NOT NULL,
    environment  TEXT NOT NULL,
    version      TEXT NOT NULL,
    receipt_id   TEXT NOT NULL,
    generation   INTEGER NOT NULL DEFAULT 0,
    seq          INTEGER NOT NULL,
    published_at TEXT NOT NULL,
    PRIMARY KEY (tenant_id, app_id, environment)
);

CREATE TABLE IF NOT EXISTS precheck_consumed (
    token      TEXT PRIMARY KEY,
    receipt_id TEXT NOT NULL,
    seq        INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS receipt (
    receipt_id          TEXT PRIMARY KEY,
    request_id          TEXT NOT NULL UNIQUE,
    tenant_id           TEXT NOT NULL,
    app_id              TEXT NOT NULL,
    environment         TEXT NOT NULL,
    version             TEXT NOT NULL,
    closure_json        TEXT NOT NULL,
    closure_fingerprint TEXT NOT NULL,
    evidence_json       TEXT NOT NULL,
    evidence_hash       TEXT NOT NULL,
    basis               TEXT NOT NULL,
    precheck_token      TEXT NOT NULL,
    seq                 INTEGER NOT NULL,
    published_at        TEXT NOT NULL,
    state               TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS duty_event (
    reviewer_id TEXT NOT NULL,
    seq         INTEGER NOT NULL,
    kind        TEXT NOT NULL,
    payload     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS person_event (
    person_id TEXT NOT NULL,
    seq       INTEGER NOT NULL,
    kind      TEXT NOT NULL,
    payload   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS software_event (
    subject TEXT NOT NULL,
    seq     INTEGER NOT NULL,
    kind    TEXT NOT NULL,
    payload TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS receipt_ack (
    receipt_id TEXT PRIMARY KEY,
    acked_at   TEXT NOT NULL,
    seq        INTEGER NOT NULL
);

-- One business operation may have been attempted by several workers.  The
-- request row is the idempotency key, so a replay returns the first result
-- instead of publishing twice.

CREATE TABLE IF NOT EXISTS request (
    request_id   TEXT PRIMARY KEY,
    op           TEXT NOT NULL,
    payload_hash TEXT NOT NULL,
    result_json  TEXT NOT NULL,
    seq          INTEGER NOT NULL,
    created_at   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS precheck (
    token          TEXT PRIMARY KEY,
    tenant_id      TEXT NOT NULL,
    app_id         TEXT NOT NULL,
    version        TEXT NOT NULL,
    environment    TEXT NOT NULL,
    basis          TEXT NOT NULL,
    evidence_hash  TEXT NOT NULL,
    closure_fingerprint TEXT NOT NULL,
    issued_at      TEXT NOT NULL,
    consumed_seq   INTEGER,
    consumed_by    TEXT
);

CREATE TABLE IF NOT EXISTS release_event (
    app_id      TEXT NOT NULL,
    environment TEXT NOT NULL,
    seq         INTEGER NOT NULL,
    kind        TEXT NOT NULL,
    payload     TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_risk_app ON risk(tenant_id, app_id);
CREATE INDEX IF NOT EXISTS idx_waiver_risk ON waiver(risk_id);
CREATE INDEX IF NOT EXISTS idx_approval_waiver ON approval(waiver_id);
CREATE INDEX IF NOT EXISTS idx_ledger_kind ON ledger(kind);
"""


# ---------------------------------------------------------------------------
# connections
# ---------------------------------------------------------------------------


def connect_rw(path: str, busy_timeout_ms: int = 15000) -> sqlite3.Connection:
    """Open a read-write connection with the pragmas this schema relies on."""
    conn = sqlite3.connect(path, timeout=busy_timeout_ms / 1000.0, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=FULL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute(f"PRAGMA busy_timeout={int(busy_timeout_ms)}")
    return conn


def connect_ro(path: str, busy_timeout_ms: int = 15000) -> sqlite3.Connection:
    """Open a genuinely read-only connection.

    ``mode=ro`` makes every write an ``attempt to write a readonly database``
    error at the SQLite layer.  It is the guarantee behind "read-only
    precheck": the code path cannot mutate the ledger even if it tried.
    """
    if not os.path.exists(path):
        raise GateError("E_STORE_BUSY", "database file does not exist", path=path)
    uri = "file:" + path.replace(os.sep, "/") + "?mode=ro"
    try:
        conn = sqlite3.connect(uri, uri=True, timeout=busy_timeout_ms / 1000.0, isolation_level=None)
    except sqlite3.Error as exc:  # pragma: no cover - platform specific
        raise GateError("E_STORE_BUSY", str(exc), path=path) from exc
    conn.row_factory = sqlite3.Row
    conn.execute(f"PRAGMA busy_timeout={int(busy_timeout_ms)}")
    return conn


def initialize(path: str) -> None:
    """Create the schema in a fresh database file."""
    parent = os.path.dirname(os.path.abspath(path))
    if parent:
        os.makedirs(parent, exist_ok=True)
    conn = connect_rw(path)
    try:
        conn.executescript(SCHEMA_SQL)
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# transactions
# ---------------------------------------------------------------------------


def _is_locked(exc: sqlite3.Error) -> bool:
    msg = str(exc).lower()
    return "locked" in msg or "busy" in msg


@contextmanager
def write_tx(conn: sqlite3.Connection, deadline_s: float = 20.0) -> Iterator[sqlite3.Connection]:
    """Serialise writers with ``BEGIN IMMEDIATE`` and bounded retry.

    ``BEGIN IMMEDIATE`` takes the write lock up front, so two processes cannot
    both validate against the same state and then both commit.  The second one
    waits, re-reads, and re-validates inside its own transaction - which is
    exactly the "re-verify inside the transaction" requirement.
    """
    deadline = time.monotonic() + deadline_s
    delay = 0.005
    while True:
        try:
            conn.execute("BEGIN IMMEDIATE")
            break
        except sqlite3.OperationalError as exc:
            if not _is_locked(exc):
                raise
            if time.monotonic() >= deadline:
                raise GateError("E_LOCK_TIMEOUT", "could not acquire the write lock") from exc
            time.sleep(delay)
            delay = min(delay * 2, 0.1)
    try:
        yield conn
    except BaseException:
        try:
            conn.execute("ROLLBACK")
        except sqlite3.Error:  # pragma: no cover - rollback of a dead tx
            pass
        raise
    else:
        conn.execute("COMMIT")


@contextmanager
def read_tx(conn: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    """A consistent read snapshot."""
    conn.execute("BEGIN")
    try:
        yield conn
    finally:
        try:
            conn.execute("COMMIT")
        except sqlite3.Error:  # pragma: no cover
            pass


# ---------------------------------------------------------------------------
# ledger
# ---------------------------------------------------------------------------


def ledger_head(conn: sqlite3.Connection) -> tuple[int, str]:
    row = conn.execute("SELECT seq, entry_hash FROM ledger ORDER BY seq DESC LIMIT 1").fetchone()
    if row is None:
        return 0, GENESIS_HASH
    return int(row["seq"]), str(row["entry_hash"])


def ledger_append(
    conn: sqlite3.Connection,
    kind: str,
    subject: str,
    payload: dict[str, Any],
    ts: str,
) -> int:
    """Append one hash-chained audit entry and return its sequence number."""
    seq, prev = ledger_head(conn)
    seq += 1
    payload_text = canonical_json(payload)
    payload_hash = sha256_text(payload_text)
    body = {
        "seq": seq,
        "ts": ts,
        "kind": kind,
        "subject": subject,
        "payload_hash": payload_hash,
        "prev_hash": prev,
    }
    entry_hash = digest_of(body)
    conn.execute(
        "INSERT INTO ledger(seq, ts, kind, subject, payload, payload_hash, prev_hash, entry_hash)"
        " VALUES (?,?,?,?,?,?,?,?)",
        (seq, ts, kind, subject, payload_text, payload_hash, prev, entry_hash),
    )
    return seq


def ledger_entries(conn: sqlite3.Connection, kind: str | None = None) -> list[dict[str, Any]]:
    if kind is None:
        rows = conn.execute("SELECT * FROM ledger ORDER BY seq").fetchall()
    else:
        rows = conn.execute("SELECT * FROM ledger WHERE kind=? ORDER BY seq", (kind,)).fetchall()
    return [dict(r) for r in rows]


def verify_chain(conn: sqlite3.Connection) -> dict[str, Any]:
    """Recompute the whole chain and report the first divergence."""
    rows = conn.execute("SELECT * FROM ledger ORDER BY seq").fetchall()
    prev = GENESIS_HASH
    expected_seq = 1
    for row in rows:
        if int(row["seq"]) != expected_seq:
            return {"ok": False, "broken_at": expected_seq, "reason": "sequence gap"}
        body = {
            "seq": int(row["seq"]),
            "ts": row["ts"],
            "kind": row["kind"],
            "subject": row["subject"],
            "payload_hash": row["payload_hash"],
            "prev_hash": row["prev_hash"],
        }
        if row["prev_hash"] != prev:
            return {"ok": False, "broken_at": int(row["seq"]), "reason": "prev_hash mismatch"}
        if digest_of(body) != row["entry_hash"]:
            return {"ok": False, "broken_at": int(row["seq"]), "reason": "entry_hash mismatch"}
        if sha256_text(row["payload"]) != row["payload_hash"]:
            return {"ok": False, "broken_at": int(row["seq"]), "reason": "payload_hash mismatch"}
        prev = row["entry_hash"]
        expected_seq += 1
    return {"ok": True, "entries": len(rows), "head": prev}


def state_seq(conn: sqlite3.Connection) -> int:
    """Current ledger sequence, used as the optimistic version of the store."""
    row = conn.execute("SELECT MAX(seq) AS s FROM ledger").fetchone()
    return int(row["s"] or 0)
