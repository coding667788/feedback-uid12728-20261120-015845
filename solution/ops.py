"""Operations: precheck, publish, approvals, waivers, registry changes, reads.

Every mutating operation follows the same shape:

1. resolve the request id (idempotent replay short-circuit);
2. open ``BEGIN IMMEDIATE`` so writers serialise on the database write lock;
3. re-read and re-validate *everything* the decision depends on;
4. write rows and append exactly one hash-chained ledger entry;
5. commit, then acknowledge the receipt in a second transaction.

Precheck and every query open ``mode=ro`` connections and cannot write even if
the code above them turns out to be buggy.
"""

from __future__ import annotations

import json
import os
from typing import Any, Callable

from . import db
from .errors import GateError
from .model import require_severity, severity_rank
from .policy import ensure_no_blockers
from .store import (
    compare_declared_closure,
    evaluate_release,
    evidence_hash,
    evidence_payload,
    load_app,
    load_app_version,
    load_tenant,
    load_waiver,
    resolve_for,
)
from .util import canonical_json, digest_of, parse_ts
from .versions import parse_constraint

# ---------------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------------

_SKIP_FIELDS = {"crash_at", "expect", "note", "worker", "label", "vars", "sync"}


def _require(op: dict[str, Any], *names: str) -> None:
    for name in names:
        if op.get(name) is None:
            raise GateError("E_MISSING_FIELD", f"operation {op.get('op')!r} needs {name!r}", field=name)


def _str(op: dict[str, Any], name: str) -> str:
    value = op.get(name)
    if not isinstance(value, str) or not value:
        raise GateError("E_BAD_TYPE", f"{name} must be a non-empty string", field=name)
    return value


def request_digest(op: dict[str, Any]) -> str:
    """Identity of a request's intent, ignoring orchestration-only fields."""
    body = {k: v for k, v in op.items() if k not in _SKIP_FIELDS}
    return digest_of(body)


# ---------------------------------------------------------------------------
# deterministic interleaving hooks
# ---------------------------------------------------------------------------

_LIFECYCLE: list[dict[str, Any]] = []


class op_scope:
    """Attach a ``sync`` spec to every operation issued inside this block.

    A worker's operations live in the case file, not in the operation itself,
    so the runner publishes the worker's ``sync`` spec here before dispatching.
    """

    def __init__(self, spec: dict[str, Any] | None) -> None:
        self.spec = spec or {}

    def __enter__(self) -> "op_scope":
        _LIFECYCLE.append(self.spec)
        return self

    def __exit__(self, *exc: object) -> None:
        _LIFECYCLE.pop()


def _hook(stage: str) -> None:
    """Pause at a named stage when the active worker asked for it.

    ``{"dir": ..., "worker": "w1", "barrier": "go", "parties": 2}`` sends the
    worker to a barrier before it starts; ``hold_after: ["revalidate"]`` pins
    it inside its write transaction once it reaches that stage.  Together these
    make every contention case reproducible instead of probabilistic.
    """
    from . import sync

    for spec in reversed(_LIFECYCLE):
        if not spec:
            continue
        directory = spec.get("dir")
        if not isinstance(directory, str):
            continue
        worker_id = str(spec.get("worker") or "w0")
        barrier = spec.get("barrier")
        if isinstance(barrier, str) and stage == "before_lock" and not spec.get("_barrier_done"):
            sync.barrier_wait(directory, barrier, worker_id, int(spec.get("parties", 2)))
            spec["_barrier_done"] = True
        if stage in (spec.get("hold_after") or []):
            sync.hold(directory, stage, worker_id)


def _lookup_request(conn, request_id: str, digest: str) -> dict[str, Any] | None:
    row = conn.execute("SELECT * FROM request WHERE request_id=?", (request_id,)).fetchone()
    if row is None:
        return None
    if row["payload_hash"] != digest:
        raise GateError(
            "E_IDEMPOTENCY_CONFLICT",
            f"request {request_id!r} was already used for different content",
            request_id=request_id,
        )
    result = json.loads(row["result_json"])
    result["replayed"] = True
    return result


def _store_request(conn, request_id: str, op: str, digest: str, result: dict[str, Any], ts: str) -> None:
    conn.execute(
        "INSERT INTO request(request_id, op, payload_hash, result_json, seq, created_at) VALUES (?,?,?,?,?,?)",
        (request_id, op, digest, canonical_json(result), db.state_seq(conn), ts),
    )


def _at(op: dict[str, Any], default: str = "2026-11-20T00:00:00Z") -> str:
    at = op.get("at", default)
    if not isinstance(at, str):
        raise GateError("E_BAD_TYPE", "'at' must be a timestamp string")
    return parse_ts(at).strftime("%Y-%m-%dT%H:%M:%SZ")


def _signature(conn, sig_id: str) -> dict[str, Any]:
    row = conn.execute("SELECT * FROM signature WHERE signature_id=?", (sig_id,)).fetchone()
    if row is None:
        raise GateError("E_UNKNOWN_REF", f"unknown signature {sig_id!r}", signature_id=sig_id)
    return dict(row)


def _reviewer(conn, reviewer_id: str) -> dict[str, Any]:
    row = conn.execute("SELECT * FROM reviewer_duty WHERE reviewer_id=?", (reviewer_id,)).fetchone()
    if row is None:
        raise GateError("E_UNKNOWN_REF", f"unknown reviewer {reviewer_id!r}", reviewer_id=reviewer_id)
    return dict(row)


def _waiver(conn, waiver_id: str) -> dict[str, Any]:
    w = load_waiver(conn, waiver_id)
    if w is None:
        raise GateError("E_UNKNOWN_REF", f"unknown waiver {waiver_id!r}", waiver_id=waiver_id)
    return w


def _risk(conn, risk_id: str) -> dict[str, Any]:
    row = conn.execute("SELECT * FROM risk WHERE risk_id=?", (risk_id,)).fetchone()
    if row is None:
        raise GateError("E_RISK_UNKNOWN", f"unknown risk {risk_id!r}", risk_id=risk_id)
    return dict(row)


def _event(conn, table: str, key_col: str, key: str, kind: str, payload: Any, seq: int) -> None:
    """Attach a typed sub-event to the ledger entry that caused it."""
    conn.execute(
        f"INSERT INTO {table}({key_col}, seq, kind, payload) VALUES (?,?,?,?)",
        (key, seq, kind, canonical_json(payload) if not isinstance(payload, str) else payload),
    )


# ---------------------------------------------------------------------------
# read-only precheck
# ---------------------------------------------------------------------------


def _revisit_history(conn, verdict) -> dict[str, Any]:
    """Detect a candidate that has returned to a state seen before.

    Two independent histories matter:

    * the app/environment authorisation-basis history - this exact decision
      basis was live once and was superseded;
    * the content-digest history of every pinned dependency - some package has
      reverted to content that was previously retired.

    Either way the gate does not reuse an old decision: the verdict is
    recomputed now, and the report says plainly that it was seen before.
    """
    prior = conn.execute(
        "SELECT * FROM app_fingerprint_history WHERE tenant_id=? AND app_id=? AND environment=?"
        " AND fingerprint=?",
        (verdict.tenant_id, verdict.app_id, verdict.environment, verdict.basis()),
    ).fetchone()
    reverted = []
    for row in verdict.closure:
        hist = conn.execute(
            "SELECT epoch, retired_at FROM software_digest_history"
            " WHERE tenant_id=? AND name=? AND version=? AND content_digest=?",
            (verdict.tenant_id, row["name"], row["version"], row["content_digest"]),
        ).fetchall()
        if any(h["retired_at"] is not None for h in hist):
            reverted.append(
                {
                    "package": f"{row['name']}@{row['version']}",
                    "digest": row["content_digest"],
                    "epochs": [h["epoch"] for h in hist],
                }
            )
    return {
        "basis_seen_before": prior is not None,
        "previous_seq": prior["first_seq"] if prior else None,
        "reverted_digests": reverted,
        "needs_fresh_judgement": bool(prior is not None or reverted),
    }


def op_precheck(db_path: str, op: dict[str, Any]) -> dict[str, Any]:
    """Read-only feasibility check that mints a precheck token.

    The token is not a capability stored in a file: it is the digest of the
    complete authorisation basis.  Publishing recomputes that basis inside its
    write transaction and rejects the token on any difference, so a token can
    never launder state that changed after precheck.
    """
    _require(op, "tenant_id", "app_id", "version", "environment")
    at = _at(op)
    tenant_id = _str(op, "tenant_id")
    app_id = _str(op, "app_id")
    version = _str(op, "version")
    environment = _str(op, "environment")

    conn = db.connect_ro(db_path)
    try:
        verdict = evaluate_release(
            conn, tenant_id=tenant_id, app_id=app_id, version=version,
            environment=environment, at=at,
        )
        app_version = load_app_version(conn, app_id, version)
        coverage = compare_declared_closure(app_version, resolve_for(conn, app_version, environment))
        payload = evidence_payload(verdict)
        return {
            "status": "ok",
            "authorized": verdict.authorized,
            "app_id": app_id,
            "version": version,
            "environment": environment,
            "at": at,
            "precheck_token": verdict.basis(),
            "basis": verdict.basis(),
            "closure_fingerprint": verdict.closure_fingerprint,
            "closure": verdict.closure,
            "risks": [r.as_dict() for r in verdict.risks],
            "blocked": list(verdict.blocked),
            "manifest": coverage,
            "revisit": _revisit_history(conn, verdict),
            "evidence_hash": evidence_hash(payload),
        }
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# publish
# ---------------------------------------------------------------------------


def op_publish(db_path: str, op: dict[str, Any], crash_at: str | None = None) -> dict[str, Any]:
    """Promote a version, re-verifying closure and authority inside the write tx."""
    _require(op, "tenant_id", "app_id", "version", "environment", "request_id", "actor")
    for field in ("tenant_id", "app_id", "version", "environment", "request_id", "actor"):
        _str(op, field)
    request_id = op["request_id"]
    at = _at(op)
    digest = request_digest(op)

    conn = db.connect_rw(db_path)
    try:
        replay = _lookup_request(conn, request_id, digest)
        if replay is not None:
            return replay

        token = op.get("precheck_token")
        if not token:
            raise GateError("E_PRECHECK_REQUIRED", "publish needs the precheck token", app_id=op["app_id"])

        receipt_id = "rcpt_" + digest_of(
            {"request_id": request_id, "app": op["app_id"],
             "version": op["version"], "env": op["environment"]}
        )[7:23]
        result: dict[str, Any] = {}

        _hook("before_lock")
        with db.write_tx(conn):
            tenant_id = op["tenant_id"]
            app_id = op["app_id"]
            version = op["version"]
            environment = op["environment"]

            used = conn.execute("SELECT * FROM precheck_consumed WHERE token=?", (token,)).fetchone()
            if used is not None:
                raise GateError(
                    "E_PRECHECK_CONSUMED", "precheck token was already used for another publish",
                    token=token, receipt_id=used["receipt_id"],
                )

            # --- re-verify everything, from scratch, in this transaction ---
            verdict = evaluate_release(
                conn, tenant_id=tenant_id, app_id=app_id, version=version,
                environment=environment, at=at,
            )
            if verdict.basis() != token:
                raise GateError(
                    "E_PRECHECK_STALE",
                    "authorisation basis changed between precheck and publish",
                    precheck_basis=token,
                    current_basis=verdict.basis(),
                    blocked=list(verdict.blocked),
                )
            ensure_no_blockers(verdict)
            _hook("revalidate")

            app_version = load_app_version(conn, app_id, version)
            coverage = compare_declared_closure(app_version, resolve_for(conn, app_version, environment))
            if not coverage["complete"]:
                raise GateError(
                    "E_MANIFEST_INCOMPLETE",
                    "declared lock does not cover the resolved dependency closure",
                    diffs=coverage["diffs"],
                )

            prior = conn.execute(
                "SELECT version FROM release WHERE tenant_id=? AND app_id=? AND environment=?",
                (tenant_id, app_id, environment),
            ).fetchone()
            previous_version = prior["version"] if prior else None
            if previous_version == version:
                raise GateError(
                    "E_POINTER_UNCHANGED", f"{app_id} already serves {version} in {environment}",
                    app_id=app_id, version=version,
                )
            _hook("before_write")

            payload = evidence_payload(verdict)
            ev_hash = evidence_hash(payload)
            seq = db.ledger_append(
                conn,
                "release.published",
                f"{app_id}:{environment}",
                {
                    "receipt_id": receipt_id,
                    "from": previous_version,
                    "to": version,
                    "evidence_hash": ev_hash,
                    "closure_fingerprint": verdict.closure_fingerprint,
                    "basis": verdict.basis(),
                    "actor": op["actor"],
                    "precheck_token": token,
                },
                at,
            )
            conn.execute(
                "INSERT INTO receipt(receipt_id, request_id, tenant_id, app_id, environment, version,"
                " closure_json, closure_fingerprint, evidence_json, evidence_hash, basis,"
                " precheck_token, seq, published_at, state)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,'committed_unacked')",
                (
                    receipt_id, request_id, tenant_id, app_id, environment, version,
                    canonical_json(verdict.closure), verdict.closure_fingerprint,
                    canonical_json(payload), ev_hash, verdict.basis(), token, seq, at,
                ),
            )
            conn.execute(
                "INSERT INTO release(tenant_id, app_id, environment, version, receipt_id, generation,"
                " seq, published_at) VALUES (?,?,?,?,?,1,?,?)"
                " ON CONFLICT(tenant_id, app_id, environment) DO UPDATE SET"
                " version=excluded.version, receipt_id=excluded.receipt_id,"
                " generation=release.generation+1, seq=excluded.seq,"
                " published_at=excluded.published_at",
                (tenant_id, app_id, environment, version, receipt_id, seq, at),
            )
            conn.execute(
                "INSERT INTO precheck_consumed(token, receipt_id, seq) VALUES (?,?,?)",
                (token, receipt_id, seq),
            )
            _record_app_fingerprint(conn, tenant_id, app_id, environment, verdict.basis(), seq)

            result = {
                "status": "ok",
                "receipt_id": receipt_id,
                "request_id": request_id,
                "tenant_id": tenant_id,
                "app_id": app_id,
                "environment": environment,
                "version": version,
                "previous_version": previous_version,
                "closure_fingerprint": verdict.closure_fingerprint,
                "evidence_hash": ev_hash,
                "published_at": at,
                "authorized": True,
                "acknowledged": False,
            }
            _store_request(conn, request_id, "publish", digest, result, at)

            if crash_at == "before_commit":  # pragma: no cover - subprocess only
                _die("before_commit")

        if crash_at == "after_commit":  # pragma: no cover - subprocess only
            _die("after_commit")

        # --- second transaction: acknowledge ------------------------------
        # Dying between the two transactions leaves a committed pointer with an
        # unacknowledged receipt - the state ``recover`` must be able to see.
        with db.write_tx(conn):
            ack_seq = db.ledger_append(
                conn, "release.acknowledged", receipt_id, {"receipt_id": receipt_id}, at
            )
            conn.execute(
                "INSERT INTO receipt_ack(receipt_id, acked_at, seq) VALUES (?,?,?)",
                (receipt_id, at, ack_seq),
            )
            conn.execute("UPDATE receipt SET state='committed_acked' WHERE receipt_id=?", (receipt_id,))
            conn.execute(
                "UPDATE request SET result_json=? WHERE request_id=?",
                (canonical_json({**result, "acknowledged": True}), request_id),
            )

        return {**result, "acknowledged": True}
    finally:
        conn.close()


def _record_app_fingerprint(conn, tenant_id: str, app_id: str, environment: str,
                            fingerprint: str, seq: int) -> None:
    conn.execute(
        "UPDATE app_fingerprint_history SET retired_seq=? WHERE tenant_id=? AND app_id=?"
        " AND environment=? AND retired_seq IS NULL",
        (seq, tenant_id, app_id, environment),
    )
    conn.execute(
        "INSERT INTO app_fingerprint_history(tenant_id, app_id, environment, fingerprint,"
        " first_seq, last_seq, retired_seq) VALUES (?,?,?,?,?,?,NULL)",
        (tenant_id, app_id, environment, fingerprint, seq, seq),
    )


def _die(point: str) -> None:  # pragma: no cover - kills this process
    """Hard-exit the worker at the chosen point, simulating a power loss."""
    import sys

    os.write(2, f"[worker] injected crash at {point}\n".encode())
    sys.stderr.flush()
    sys.stdout.flush()
    os._exit(70)


# ---------------------------------------------------------------------------
# approvals and waivers
# ---------------------------------------------------------------------------


def op_approve(db_path: str, op: dict[str, Any]) -> dict[str, Any]:
    """Record a fresh approval, snapshotting the live state it is bound to."""
    _require(op, "waiver_id", "reviewer_id", "signature_id", "approval_id", "request_id")
    at = _at(op)
    digest = request_digest(op)
    conn = db.connect_rw(db_path)
    try:
        replay = _lookup_request(conn, op["request_id"], digest)
        if replay is not None:
            return replay
        _hook("before_lock")
        with db.write_tx(conn):
            w = _waiver(conn, op["waiver_id"])
            risk = _risk(conn, w["risk_id"])
            reviewer = _reviewer(conn, op["reviewer_id"])
            sig = _signature(conn, op["signature_id"])
            _hook("loaded")

            if w["status"] != "active":
                raise GateError("E_WAIVER_REVOKED", f"waiver is {w['status']}", waiver_id=w["waiver_id"])
            if at >= w["repair_deadline"]:
                raise GateError("E_WAIVER_EXPIRED", "waiver repair deadline already reached",
                                at=at, deadline=w["repair_deadline"])
            if reviewer["tenant_id"] != w["tenant_id"]:
                raise GateError("E_TENANT_MISMATCH", "reviewer belongs to another tenant")
            if reviewer["revoked_at"] is not None:
                raise GateError("E_APPROVAL_DUTY_REVOKED", "reviewer duty is revoked",
                                reviewer_id=reviewer["reviewer_id"])
            if reviewer["active_from"] > at:
                raise GateError("E_APPROVAL_DUTY_REVOKED", "reviewer is not yet on duty")
            role = op.get("role", reviewer["role"])
            if role != reviewer["role"]:
                raise GateError("E_APPROVAL_ROLE_CONFLICT",
                                "signature must use the post the reviewer currently holds",
                                role=role, held=reviewer["role"])
            if sig["reviewer_id"] != reviewer["reviewer_id"]:
                raise GateError("E_APPROVAL_SIGNATURE", "signature was not issued to this reviewer")
            if sig["tenant_id"] != w["tenant_id"]:
                raise GateError("E_TENANT_MISMATCH", "signature belongs to another tenant")
            if sig["status"] != "valid":
                raise GateError("E_APPROVAL_SIGNATURE", f"signature status is {sig['status']!r}",
                                status=sig["status"])
            if risk["severity"] == "critical":
                raise GateError("E_APPROVAL_SEVERITY", "critical severity cannot be approved away")

            later_approval = conn.execute(
                "SELECT approval_id FROM approval WHERE waiver_id=? AND reviewer_id=? AND status='active'",
                (w["waiver_id"], reviewer["reviewer_id"]),
            ).fetchone()
            if later_approval is not None:
                raise GateError(
                    "E_APPROVAL_DUPLICATE",
                    "reviewer already holds a live approval for this waiver",
                    approval_id=later_approval["approval_id"],
                )

            app_version = load_app_version(conn, w["app_id"], op.get("app_version") or "")
            row = {
                "approval_id": op["approval_id"],
                "waiver_id": w["waiver_id"],
                "reviewer_id": reviewer["reviewer_id"],
                "role": role,
                "signature_id": sig["signature_id"],
                "decision": op.get("decision", "grant"),
                "app_id": w["app_id"],
                "app_version": app_version["version"],
                "environment": w["environment"],
                "risk_id": risk["risk_id"],
                "content_digest": w["content_digest"],
                "evidence_version": w["evidence_version"],
                "severity_snapshot": risk["severity"],
                "deadline_snapshot": w["repair_deadline"],
                "duty_epoch": reviewer["duty_epoch"],
                "duty_version": reviewer["duty_version"],
                "signed_at": at,
            }
            seq = db.ledger_append(
                conn, "approval.granted", row["approval_id"],
                {
                    "waiver_id": row["waiver_id"], "reviewer_id": row["reviewer_id"],
                    "person_id": reviewer["person_id"], "role": role,
                    "app_id": row["app_id"], "app_version": row["app_version"],
                    "environment": row["environment"], "risk_id": row["risk_id"],
                    "content_digest": row["content_digest"],
                    "severity_snapshot": row["severity_snapshot"],
                    "deadline_snapshot": row["deadline_snapshot"],
                    "duty_epoch": row["duty_epoch"], "duty_version": row["duty_version"],
                },
                at,
            )
            conn.execute(
                "INSERT INTO approval(approval_id, waiver_id, reviewer_id, role, signature_id, decision,"
                " app_id, app_version, environment, risk_id, content_digest, evidence_version,"
                " severity_snapshot, deadline_snapshot, duty_epoch, duty_version, signed_at, status,"
                " revoked_reason, seq) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'active',NULL,?)",
                (
                    row["approval_id"], row["waiver_id"], row["reviewer_id"], row["role"],
                    row["signature_id"], row["decision"], row["app_id"], row["app_version"],
                    row["environment"], row["risk_id"], row["content_digest"],
                    row["evidence_version"], row["severity_snapshot"], row["deadline_snapshot"],
                    row["duty_epoch"], row["duty_version"], row["signed_at"], seq,
                ),
            )
            _event(conn, "approval_event", "approval_id", row["approval_id"], "granted",
                   {"reviewer_id": row["reviewer_id"], "role": role, "seq": seq}, seq)
            result = {
                "status": "ok", "approval_id": row["approval_id"], "waiver_id": row["waiver_id"],
                "reviewer_id": row["reviewer_id"], "role": role,
                "severity_snapshot": row["severity_snapshot"], "signed_at": at,
            }
            _store_request(conn, op["request_id"], "approve", digest, result, at)
        return result
    finally:
        conn.close()


def op_revoke_approval(db_path: str, op: dict[str, Any]) -> dict[str, Any]:
    _require(op, "approval_id", "request_id", "actor")
    at = _at(op)
    digest = request_digest(op)
    reason = op.get("reason", "revoked")
    conn = db.connect_rw(db_path)
    try:
        replay = _lookup_request(conn, op["request_id"], digest)
        if replay is not None:
            return replay
        with db.write_tx(conn):
            row = conn.execute("SELECT * FROM approval WHERE approval_id=?",
                               (op["approval_id"],)).fetchone()
            if row is None:
                raise GateError("E_UNKNOWN_REF", "unknown approval", approval_id=op["approval_id"])
            if row["status"] != "active":
                raise GateError("E_APPROVAL_STALE", f"approval is already {row['status']}",
                                approval_id=op["approval_id"])
            conn.execute(
                "UPDATE approval SET status='revoked', revoked_reason=? WHERE approval_id=?",
                (reason, op["approval_id"]),
            )
            seq = db.ledger_append(
                conn, "approval.revoked", row["approval_id"],
                {"reason": reason, "actor": op["actor"], "reviewer_id": row["reviewer_id"]}, at,
            )
            _event(conn, "approval_event", "approval_id", row["approval_id"], "revoked",
                   {"reason": reason, "actor": op["actor"]}, seq)
            result = {"status": "ok", "approval_id": row["approval_id"], "revoked": True,
                      "reason": reason}
            _store_request(conn, op["request_id"], "revoke_approval", digest, result, at)
        return result
    finally:
        conn.close()


def op_revoke_waiver(db_path: str, op: dict[str, Any]) -> dict[str, Any]:
    _require(op, "waiver_id", "request_id", "actor")
    at = _at(op)
    digest = request_digest(op)
    conn = db.connect_rw(db_path)
    try:
        replay = _lookup_request(conn, op["request_id"], digest)
        if replay is not None:
            return replay
        with db.write_tx(conn):
            w = _waiver(conn, op["waiver_id"])
            if w["status"] != "active":
                raise GateError("E_WAIVER_REVOKED", f"waiver is already {w['status']}",
                                waiver_id=w["waiver_id"])
            conn.execute("UPDATE waiver SET status='revoked', updated_seq=? WHERE waiver_id=?",
                         (db.state_seq(conn), w["waiver_id"]))
            seq = db.ledger_append(
                conn, "waiver.revoked", w["waiver_id"],
                {"actor": op["actor"], "reason": op.get("reason", "")}, at,
            )
            _event(conn, "waiver_event", "waiver_id", w["waiver_id"], "revoked",
                   {"actor": op["actor"], "reason": op.get("reason", "")}, seq)
            result = {"status": "ok", "waiver_id": w["waiver_id"], "revoked": True}
            _store_request(conn, op["request_id"], "revoke_waiver", digest, result, at)
        return result
    finally:
        conn.close()


def op_extend_waiver(db_path: str, op: dict[str, Any]) -> dict[str, Any]:
    """Move the repair deadline.  Every prior approval snapshot is now stale."""
    _require(op, "waiver_id", "repair_deadline", "request_id", "actor")
    at = _at(op)
    digest = request_digest(op)
    new_deadline = parse_ts(_str(op, "repair_deadline")).strftime("%Y-%m-%dT%H:%M:%SZ")
    conn = db.connect_rw(db_path)
    try:
        replay = _lookup_request(conn, op["request_id"], digest)
        if replay is not None:
            return replay
        with db.write_tx(conn):
            w = _waiver(conn, op["waiver_id"])
            if w["status"] != "active":
                raise GateError("E_WAIVER_REVOKED", f"waiver is {w['status']}", waiver_id=w["waiver_id"])
            if new_deadline <= w["repair_deadline"]:
                raise GateError("E_BAD_FORMAT", "extension must move the deadline later",
                                value=new_deadline, current=w["repair_deadline"])
            conn.execute("UPDATE waiver SET repair_deadline=?, updated_seq=? WHERE waiver_id=?",
                         (new_deadline, db.state_seq(conn), w["waiver_id"]))
            seq = db.ledger_append(
                conn, "waiver.extended", w["waiver_id"],
                {"from": w["repair_deadline"], "to": new_deadline, "actor": op["actor"]}, at,
            )
            _event(conn, "waiver_event", "waiver_id", w["waiver_id"], "extended",
                   {"from": w["repair_deadline"], "to": new_deadline}, seq)
            result = {"status": "ok", "waiver_id": w["waiver_id"], "repair_deadline": new_deadline,
                      "previous_deadline": w["repair_deadline"], "invalidates_approvals": True}
            _store_request(conn, op["request_id"], "extend_waiver", digest, result, at)
        return result
    finally:
        conn.close()


def op_request_waiver(db_path: str, op: dict[str, Any]) -> dict[str, Any]:
    _require(op, "waiver_id", "risk_id", "environment", "evidence_version",
             "repair_deadline", "requested_by", "request_id")
    at = _at(op)
    digest = request_digest(op)
    deadline = parse_ts(_str(op, "repair_deadline")).strftime("%Y-%m-%dT%H:%M:%SZ")
    conn = db.connect_rw(db_path)
    try:
        replay = _lookup_request(conn, op["request_id"], digest)
        if replay is not None:
            return replay
        with db.write_tx(conn):
            risk = _risk(conn, op["risk_id"])
            if risk["severity"] == "critical":
                raise GateError("E_APPROVAL_SEVERITY", "critical severity cannot be waived")
            if risk["status"] == "fixed":
                raise GateError("E_RISK_OPEN", "risk already carries a verified fix",
                                risk_id=risk["risk_id"])
            if deadline < at:
                raise GateError("E_TIME_ORDER", "a waiver cannot expire before it is created")
            if op["evidence_version"] != risk["dep_version"]:
                raise GateError("E_WAIVER_EVIDENCE",
                                "evidence version must equal the risky dependency version",
                                expected=risk["dep_version"], actual=op["evidence_version"])
            app = load_app(conn, risk["app_id"])
            if app["tenant_id"] != risk["tenant_id"]:
                raise GateError("E_TENANT_MISMATCH", "risk application belongs to another tenant")
            tenant = load_tenant(conn, risk["tenant_id"])
            if op["environment"] not in json.loads(tenant["environments"]):
                raise GateError("E_ENV_UNKNOWN", "environment is not declared",
                                environment=op["environment"])
            seq = db.ledger_append(
                conn, "waiver.created", op["waiver_id"],
                {"risk_id": risk["risk_id"], "deadline": deadline,
                 "environment": op["environment"], "requested_by": op["requested_by"]}, at,
            )
            conn.execute(
                "INSERT INTO waiver(waiver_id, risk_id, tenant_id, app_id, content_digest, environment,"
                " evidence_version, repair_deadline, requested_by, status, created_at, updated_seq)"
                " VALUES (?,?,?,?,?,?,?,?,?,'active',?,?)",
                (
                    op["waiver_id"], risk["risk_id"], risk["tenant_id"], risk["app_id"],
                    risk["content_digest"], op["environment"], op["evidence_version"],
                    deadline, op["requested_by"], at, seq,
                ),
            )
            _event(conn, "waiver_event", "waiver_id", op["waiver_id"], "created",
                   {"risk_id": risk["risk_id"], "deadline": deadline}, seq)
            result = {"status": "ok", "waiver_id": op["waiver_id"], "risk_id": risk["risk_id"],
                      "repair_deadline": deadline, "environment": op["environment"]}
            _store_request(conn, op["request_id"], "request_waiver", digest, result, at)
        return result
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# registry changes that invalidate prior decisions
# ---------------------------------------------------------------------------


def op_raise_risk(db_path: str, op: dict[str, Any]) -> dict[str, Any]:
    """Escalate severity; approvals signed at the old level stop counting."""
    _require(op, "risk_id", "severity", "request_id", "actor")
    at = _at(op)
    digest = request_digest(op)
    new_sev = require_severity(op["severity"])
    conn = db.connect_rw(db_path)
    try:
        replay = _lookup_request(conn, op["request_id"], digest)
        if replay is not None:
            return replay
        with db.write_tx(conn):
            risk = _risk(conn, op["risk_id"])
            if severity_rank(new_sev) <= severity_rank(risk["severity"]):
                raise GateError("E_BAD_FORMAT", "escalation must strictly raise severity",
                                value=new_sev, current=risk["severity"])
            conn.execute("UPDATE risk SET severity=?, updated_seq=? WHERE risk_id=?",
                         (new_sev, db.state_seq(conn), risk["risk_id"]))
            seq = db.ledger_append(
                conn, "risk.severity_raised", risk["risk_id"],
                {"from": risk["severity"], "to": new_sev, "actor": op["actor"]}, at,
            )
            _event(conn, "risk_event", "risk_id", risk["risk_id"], "severity_raised",
                   {"from": risk["severity"], "to": new_sev}, seq)
            result = {"status": "ok", "risk_id": risk["risk_id"], "previous": risk["severity"],
                      "severity": new_sev, "invalidates_approvals": True}
            _store_request(conn, op["request_id"], "raise_risk", digest, result, at)
        return result
    finally:
        conn.close()


def op_transfer_reviewer(db_path: str, op: dict[str, Any]) -> dict[str, Any]:
    """Move a reviewer to a new post, revoking duty and every live approval.

    The revocation is recorded before the new post is granted, so the audit
    trail can never show an unbroken record of authority for someone who left.
    """
    _require(op, "reviewer_id", "role", "request_id", "actor")
    at = _at(op)
    digest = request_digest(op)
    conn = db.connect_rw(db_path)
    try:
        replay = _lookup_request(conn, op["request_id"], digest)
        if replay is not None:
            return replay
        _hook("before_lock")
        with db.write_tx(conn):
            reviewer = _reviewer(conn, op["reviewer_id"])
            if reviewer["role"] == op["role"]:
                raise GateError("E_BAD_FORMAT", "transfer must change the post", role=op["role"])
            registered = {
                r["role"] for r in conn.execute(
                    "SELECT role FROM role_registry WHERE tenant_id=?", (reviewer["tenant_id"],)
                ).fetchall()
            }
            if op["role"] not in registered:
                raise GateError("E_ROLE_UNKNOWN", "target post is not registered for this tenant",
                                role=op["role"])
            held = conn.execute(
                "SELECT role FROM person_role WHERE person_id=? AND tenant_id=?",
                (reviewer["person_id"], reviewer["tenant_id"]),
            ).fetchall()
            other_roles = {h["role"] for h in held} - {reviewer["role"]}
            if other_roles:
                raise GateError(
                    "E_SEGREGATION", "person already holds another review post",
                    person_id=reviewer["person_id"], roles=sorted(other_roles | {op["role"]}),
                )
            conn.execute(
                "DELETE FROM person_role WHERE person_id=? AND tenant_id=? AND role=?",
                (reviewer["person_id"], reviewer["tenant_id"], reviewer["role"]),
            )
            conn.execute(
                "INSERT OR IGNORE INTO person_role(person_id, tenant_id, role) VALUES (?,?,?)",
                (reviewer["person_id"], reviewer["tenant_id"], op["role"]),
            )
            conn.execute(
                "UPDATE reviewer_duty SET role=?, duty_epoch=duty_epoch+1, duty_version=duty_version+1,"
                " updated_seq=? WHERE reviewer_id=?",
                (op["role"], db.state_seq(conn), reviewer["reviewer_id"]),
            )
            revoked = conn.execute(
                "SELECT approval_id FROM approval WHERE reviewer_id=? AND status='active'",
                (reviewer["reviewer_id"],),
            ).fetchall()
            for r in revoked:
                conn.execute(
                    "UPDATE approval SET status='revoked', revoked_reason='reviewer transferred'"
                    " WHERE approval_id=?", (r["approval_id"],),
                )
            seq = db.ledger_append(
                conn, "duty.transferred", reviewer["reviewer_id"],
                {"from_role": reviewer["role"], "to_role": op["role"],
                 "revoked_approvals": [r["approval_id"] for r in revoked], "actor": op["actor"]},
                at,
            )
            _event(conn, "duty_event", "reviewer_id", reviewer["reviewer_id"], "transferred",
                   {"from_role": reviewer["role"], "to_role": op["role"],
                    "revoked_approvals": [r["approval_id"] for r in revoked]}, seq)
            result = {"status": "ok", "reviewer_id": reviewer["reviewer_id"],
                      "from_role": reviewer["role"], "role": op["role"],
                      "revoked_approvals": [r["approval_id"] for r in revoked]}
            _store_request(conn, op["request_id"], "transfer_reviewer", digest, result, at)
        return result
    finally:
        conn.close()


def op_bump_duty(db_path: str, op: dict[str, Any]) -> dict[str, Any]:
    """Re-attest a reviewer's duty without changing their post."""
    _require(op, "reviewer_id", "request_id", "actor")
    at = _at(op)
    digest = request_digest(op)
    bump = int(op.get("bump_epoch", 1))
    if bump < 1:
        raise GateError("E_BAD_FORMAT", "bump_epoch must be >= 1")
    conn = db.connect_rw(db_path)
    try:
        replay = _lookup_request(conn, op["request_id"], digest)
        if replay is not None:
            return replay
        with db.write_tx(conn):
            reviewer = _reviewer(conn, op["reviewer_id"])
            conn.execute(
                "UPDATE reviewer_duty SET duty_epoch=duty_epoch+?, duty_version=duty_version+1,"
                " updated_seq=? WHERE reviewer_id=?",
                (bump, db.state_seq(conn), reviewer["reviewer_id"]),
            )
            seq = db.ledger_append(
                conn, "duty.renewed", reviewer["reviewer_id"],
                {"role": reviewer["role"], "from_epoch": reviewer["duty_epoch"],
                 "bump": bump, "actor": op["actor"]}, at,
            )
            _event(conn, "duty_event", "reviewer_id", reviewer["reviewer_id"], "renewed",
                   {"from_epoch": reviewer["duty_epoch"], "bump": bump}, seq)
            result = {"status": "ok", "reviewer_id": reviewer["reviewer_id"],
                      "duty_epoch": reviewer["duty_epoch"] + bump}
            _store_request(conn, op["request_id"], "bump_duty", digest, result, at)
        return result
    finally:
        conn.close()


def op_register_person(db_path: str, op: dict[str, Any]) -> dict[str, Any]:
    """Register one human under one post.  Two posts is a violation."""
    _require(op, "person_id", "tenant_id", "request_id")
    at = _at(op)
    digest = request_digest(op)
    posts = op.get("posts") or [op.get("role")] if op.get("role") else op.get("posts")
    if not isinstance(posts, list) or not posts or any(not isinstance(p, str) for p in posts):
        raise GateError("E_MISSING_FIELD", "register_person needs a non-empty 'posts' list")
    conn = db.connect_rw(db_path)
    try:
        replay = _lookup_request(conn, op["request_id"], digest)
        if replay is not None:
            return replay
        with db.write_tx(conn):
            load_tenant(conn, op["tenant_id"])
            existing = conn.execute(
                "SELECT role FROM person_role WHERE person_id=? AND tenant_id=?",
                (op["person_id"], op["tenant_id"]),
            ).fetchall()
            held = {r["role"] for r in existing} | set(posts)
            if len(held) > 1:
                raise GateError(
                    "E_SEGREGATION",
                    "one person cannot hold two independent review posts",
                    person_id=op["person_id"], roles=sorted(held),
                )
            registered = {
                r["role"] for r in conn.execute(
                    "SELECT role FROM role_registry WHERE tenant_id=?", (op["tenant_id"],)
                ).fetchall()
            }
            for role in posts:
                if role not in registered:
                    raise GateError("E_ROLE_UNKNOWN", "post is not registered", role=role)
            seq = db.ledger_append(
                conn, "person.registered", op["person_id"],
                {"tenant_id": op["tenant_id"], "posts": sorted(held)}, at,
            )
            for role in posts:
                conn.execute(
                    "INSERT OR IGNORE INTO person_role(person_id, tenant_id, role) VALUES (?,?,?)",
                    (op["person_id"], op["tenant_id"], role),
                )
            _event(conn, "person_event", "person_id", op["person_id"], "registered",
                   {"posts": sorted(held)}, seq)
            result = {"status": "ok", "person_id": op["person_id"], "posts": sorted(held)}
            _store_request(conn, op["request_id"], "register_person", digest, result, at)
        return result
    finally:
        conn.close()


def op_register_software(db_path: str, op: dict[str, Any]) -> dict[str, Any]:
    """Add or re-publish a package version, tracking content epochs.

    Re-publishing identical content is idempotent.  New content under an
    existing version retires the old content and bumps the epoch.  Publishing
    content that was already retired is a rollback to a previously seen digest:
    it is refused, and the refusal is written to the ledger in its own short
    transaction so that the attempt is auditable even though nothing changed.
    """
    _require(op, "tenant_id", "name", "version", "content_digest", "request_id")
    at = _at(op)
    digest = request_digest(op)
    request_id = op["request_id"]
    conn = db.connect_rw(db_path)
    try:
        replay = _lookup_request(conn, request_id, digest)
        if replay is not None:
            return replay
        try:
            with db.write_tx(conn):
                result = _register_software_tx(conn, op, at)
                _store_request(conn, request_id, "register_software", digest, result, at)
        except GateError as exc:
            if exc.code != "E_DIGEST_REVERTED":
                raise
            # The mutation rolled back; record the refused attempt separately.
            with db.write_tx(conn):
                seq = db.ledger_append(
                    conn, "software.revert_refused", f"{op['name']}@{op['version']}",
                    {"digest": op["content_digest"], "reason": exc.code,
                     "detail": exc.detail, "context": exc.ctx}, at,
                )
                _event(conn, "software_event", "subject", f"{op['name']}@{op['version']}",
                       "revert_refused", {"digest": op["content_digest"]}, seq)
            raise
        return result
    finally:
        conn.close()


def _register_software_tx(conn, op: dict[str, Any], at: str) -> dict[str, Any]:
    tenant_id = op["tenant_id"]
    load_tenant(conn, tenant_id)
    name, version, new_digest = op["name"], op["version"], op["content_digest"]
    row = conn.execute(
        "SELECT * FROM software WHERE tenant_id=? AND name=? AND version=?",
        (tenant_id, name, version),
    ).fetchone()
    history = conn.execute(
        "SELECT content_digest, epoch, retired_at FROM software_digest_history"
        " WHERE tenant_id=? AND name=? AND version=? ORDER BY epoch",
        (tenant_id, name, version),
    ).fetchall()
    seen = {h["content_digest"]: h for h in history}
    current_epoch = max((h["epoch"] for h in history), default=0)

    if row is None:
        epoch = 1
        seq = db.ledger_append(
            conn, "software.registered", f"{name}@{version}",
            {"digest": new_digest, "epoch": epoch, "outcome": "added"}, at,
        )
        conn.execute(
            "INSERT INTO software(tenant_id, name, version, content_digest, published_at,"
            " allowed_envs, superseded, revoked_at, updated_seq) VALUES (?,?,?,?,?,?,0,NULL,?)",
            (tenant_id, name, version, new_digest, at,
             canonical_json(op.get("allowed_envs") or []) or None, seq),
        )
        conn.execute(
            "INSERT INTO software_digest_history(tenant_id, name, version, content_digest,"
            " epoch, seen_at, retired_at) VALUES (?,?,?,?,?,?,NULL)",
            (tenant_id, name, version, new_digest, epoch, at),
        )
        deps = op.get("deps") or {}
        if not isinstance(deps, dict):
            raise GateError("E_BAD_TYPE", "deps must be an object")
        for dep_name, cons in deps.items():
            conn.execute(
                "INSERT INTO software_dep(tenant_id, name, version, dep_name, constraint_json)"
                " VALUES (?,?,?,?,?)",
                (tenant_id, name, version, dep_name, canonical_json(parse_constraint(cons))),
            )
        outcome = "added"
    elif row["content_digest"] == new_digest and row["revoked_at"] is None:
        epoch = current_epoch
        outcome = "unchanged"
    elif new_digest in seen:
        raise GateError(
            "E_DIGEST_REVERTED",
            "candidate reverted to a previously seen content digest",
            name=name, version=version, digest=new_digest,
            previously_seen_epoch=seen[new_digest]["epoch"],
            current_digest=row["content_digest"],
        )
    else:
        epoch = current_epoch + 1
        seq = db.ledger_append(
            conn, "software.content_changed", f"{name}@{version}",
            {"from": row["content_digest"], "to": new_digest, "epoch": epoch}, at,
        )
        conn.execute(
            "UPDATE software_digest_history SET retired_at=? WHERE tenant_id=? AND name=?"
            " AND version=? AND retired_at IS NULL",
            (at, tenant_id, name, version),
        )
        conn.execute(
            "INSERT INTO software_digest_history(tenant_id, name, version, content_digest,"
            " epoch, seen_at, retired_at) VALUES (?,?,?,?,?,?,NULL)",
            (tenant_id, name, version, new_digest, epoch, at),
        )
        conn.execute(
            "UPDATE software SET content_digest=?, published_at=?, revoked_at=NULL, updated_seq=?"
            " WHERE tenant_id=? AND name=? AND version=?",
            (new_digest, at, seq, tenant_id, name, version),
        )
        outcome = "content_changed"

    return {"status": "ok", "name": name, "version": version,
            "content_digest": new_digest, "epoch": epoch, "outcome": outcome}


def op_register_risk(db_path: str, op: dict[str, Any]) -> dict[str, Any]:
    """Register a new finding against a package the release would ship.

    This is the "risk appears after precheck" path: the basis digest changes,
    so any precheck token minted earlier is refused at publish time.
    """
    _require(op, "risk_id", "tenant_id", "app_id", "dep_name", "dep_version",
             "content_digest", "severity", "request_id")
    at = _at(op)
    digest = request_digest(op)
    severity = require_severity(op["severity"])
    conn = db.connect_rw(db_path)
    try:
        replay = _lookup_request(conn, op["request_id"], digest)
        if replay is not None:
            return replay
        with db.write_tx(conn):
            app = load_app(conn, op["app_id"])
            if app["tenant_id"] != op["tenant_id"]:
                raise GateError("E_TENANT_MISMATCH", "risk tenant differs from its application")
            seq = db.ledger_append(
                conn, "risk.registered", op["risk_id"],
                {"app_id": op["app_id"], "package": f"{op['dep_name']}@{op['dep_version']}",
                 "content_digest": op["content_digest"], "severity": severity}, at,
            )
            conn.execute(
                "INSERT INTO risk(risk_id, tenant_id, app_id, dep_name, dep_version, content_digest,"
                " severity, status, registered_at, updated_seq) VALUES (?,?,?,?,?,?,?,'open',?,?)",
                (op["risk_id"], op["tenant_id"], op["app_id"], op["dep_name"], op["dep_version"],
                 op["content_digest"], severity, at, seq),
            )
            _event(conn, "risk_event", "risk_id", op["risk_id"], "registered",
                   {"severity": severity, "package": f"{op['dep_name']}@{op['dep_version']}"}, seq)
            result = {"status": "ok", "risk_id": op["risk_id"], "severity": severity,
                      "app_id": op["app_id"]}
            _store_request(conn, op["request_id"], "register_risk", digest, result, at)
        return result
    finally:
        conn.close()


def op_record_fix(db_path: str, op: dict[str, Any]) -> dict[str, Any]:
    _require(op, "fix_id", "risk_id", "content_digest", "request_id")
    at = _at(op)
    digest = request_digest(op)
    verified = op.get("verified", True)
    if not isinstance(verified, bool):
        raise GateError("E_BAD_TYPE", "verified must be a boolean")
    conn = db.connect_rw(db_path)
    try:
        replay = _lookup_request(conn, op["request_id"], digest)
        if replay is not None:
            return replay
        with db.write_tx(conn):
            risk = _risk(conn, op["risk_id"])
            if op["content_digest"] != risk["content_digest"]:
                raise GateError(
                    "E_DIGEST_MISMATCH",
                    "fix evidence digest does not match the registered risk",
                    expected=risk["content_digest"], actual=op["content_digest"],
                )
            evidence_version = op.get("evidence_version") or risk["dep_version"]
            seq = db.ledger_append(
                conn, "risk.fix_recorded", risk["risk_id"],
                {"fix_id": op["fix_id"], "verified": bool(verified),
                 "evidence_version": evidence_version,
                 "content_digest": op["content_digest"]}, at,
            )
            conn.execute(
                "INSERT INTO fix_signal(fix_id, risk_id, evidence_version, content_digest, fixed_at,"
                " verified, seq) VALUES (?,?,?,?,?,?,?)",
                (op["fix_id"], risk["risk_id"], evidence_version, op["content_digest"], at,
                 1 if verified else 0, seq),
            )
            if verified:
                conn.execute("UPDATE risk SET status='fixed', updated_seq=? WHERE risk_id=?",
                             (seq, risk["risk_id"]))
            _event(conn, "risk_event", "risk_id", risk["risk_id"], "fix_recorded",
                   {"fix_id": op["fix_id"], "verified": bool(verified)}, seq)
            result = {"status": "ok", "risk_id": risk["risk_id"], "fix_id": op["fix_id"],
                      "verified": bool(verified),
                      "risk_status": "fixed" if verified else risk["status"]}
            _store_request(conn, op["request_id"], "record_fix", digest, result, at)
        return result
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# read-only views
# ---------------------------------------------------------------------------


def op_launch_query(db_path: str, op: dict[str, Any]) -> dict[str, Any]:
    """Read-only check of what an environment serves *now*, and whether it holds."""
    _require(op, "tenant_id", "app_id", "environment")
    at = _at(op)
    conn = db.connect_ro(db_path)
    try:
        pointer = conn.execute(
            "SELECT * FROM release WHERE tenant_id=? AND app_id=? AND environment=?",
            (op["tenant_id"], op["app_id"], op["environment"]),
        ).fetchone()
        if pointer is None:
            return {"status": "ok", "live": None, "authorized": False, "reason": "E_NO_RELEASE",
                    "app_id": op["app_id"], "environment": op["environment"], "at": at}
        receipt = conn.execute("SELECT * FROM receipt WHERE receipt_id=?",
                               (pointer["receipt_id"],)).fetchone()
        verdict = evaluate_release(
            conn, tenant_id=op["tenant_id"], app_id=op["app_id"],
            version=pointer["version"], environment=op["environment"], at=at,
        )
        current = evidence_hash(evidence_payload(verdict))
        revoked = [
            r.waiver_id for r in verdict.risks
            if r.code in {"E_WAIVER_REVOKED", "E_WAIVER_EXPIRED"} and r.waiver_id
        ]
        return {
            "status": "ok",
            "live": {"version": pointer["version"], "receipt_id": pointer["receipt_id"],
                     "published_at": pointer["published_at"], "generation": pointer["generation"]},
            "authorized": verdict.authorized,
            "blocked": list(verdict.blocked),
            "risks": [r.as_dict() for r in verdict.risks],
            "recorded_evidence_hash": receipt["evidence_hash"] if receipt else None,
            "current_evidence_hash": current,
            "history_matches_now": bool(receipt) and receipt["evidence_hash"] == current,
            "revoked_waivers": revoked,
            "closure_fingerprint": verdict.closure_fingerprint,
            "at": at,
        }
    finally:
        conn.close()


def op_receipt_query(db_path: str, op: dict[str, Any]) -> dict[str, Any]:
    if not (op.get("receipt_id") or op.get("request_id") or op.get("app_id")):
        raise GateError("E_MISSING_FIELD", "receipt query needs receipt_id, request_id or app_id")
    conn = db.connect_ro(db_path)
    try:
        if op.get("receipt_id"):
            row = conn.execute("SELECT * FROM receipt WHERE receipt_id=?",
                               (op["receipt_id"],)).fetchone()
        elif op.get("request_id"):
            row = conn.execute("SELECT * FROM receipt WHERE request_id=?",
                               (op["request_id"],)).fetchone()
        else:
            rows = conn.execute(
                "SELECT * FROM receipt WHERE tenant_id=? AND app_id=? ORDER BY published_at, seq",
                (op.get("tenant_id"), op["app_id"]),
            ).fetchall()
            return {
                "status": "ok",
                "receipts": [
                    {"receipt_id": r["receipt_id"], "version": r["version"],
                     "environment": r["environment"], "published_at": r["published_at"],
                     "evidence_hash": r["evidence_hash"], "state": r["state"],
                     "acknowledged": _acked(conn, r["receipt_id"])}
                    for r in rows
                ],
            }
        if row is None:
            raise GateError("E_UNKNOWN_REF", "receipt not found",
                            receipt_id=op.get("receipt_id"), request_id=op.get("request_id"))
        return _receipt_view(conn, row)
    finally:
        conn.close()


def _acked(conn, receipt_id: str) -> bool:
    return conn.execute("SELECT 1 FROM receipt_ack WHERE receipt_id=?", (receipt_id,)).fetchone() is not None


def _receipt_view(conn, row) -> dict[str, Any]:
    ack = conn.execute("SELECT acked_at FROM receipt_ack WHERE receipt_id=?",
                       (row["receipt_id"],)).fetchone()
    stored = json.loads(row["evidence_json"])
    recomputed = evidence_hash(stored)
    return {
        "status": "ok",
        "receipt_id": row["receipt_id"],
        "request_id": row["request_id"],
        "app_id": row["app_id"],
        "environment": row["environment"],
        "version": row["version"],
        "published_at": row["published_at"],
        "state": row["state"],
        "acknowledged_at": ack["acked_at"] if ack else None,
        "acknowledged": ack is not None,
        "closure_fingerprint": row["closure_fingerprint"],
        "evidence_hash": row["evidence_hash"],
        "evidence_hash_recomputed": recomputed,
        "evidence_intact": recomputed == row["evidence_hash"],
        "closure": json.loads(row["closure_json"]),
        "risks": stored["risks"],
        "signature": digest_of({
            "receipt_id": row["receipt_id"],
            "evidence_hash": row["evidence_hash"],
            "closure_fingerprint": row["closure_fingerprint"],
        }),
    }


def op_audit(db_path: str, op: dict[str, Any]) -> dict[str, Any]:
    conn = db.connect_ro(db_path)
    try:
        rows = db.ledger_entries(conn, op.get("kind"))
        return {
            "status": "ok",
            "chain": db.verify_chain(conn),
            "entries": [
                {"seq": r["seq"], "ts": r["ts"], "kind": r["kind"], "subject": r["subject"],
                 "payload": json.loads(r["payload"]), "payload_hash": r["payload_hash"],
                 "prev_hash": r["prev_hash"], "entry_hash": r["entry_hash"]}
                for r in rows
            ],
        }
    finally:
        conn.close()


def op_recover(db_path: str, op: dict[str, Any]) -> dict[str, Any]:
    """Find receipts committed without acknowledgement, and optionally repair them."""
    at = _at(op)
    apply = bool(op.get("apply", False))
    if not apply:
        conn = db.connect_ro(db_path)
        try:
            rows = conn.execute("SELECT * FROM receipt WHERE state='committed_unacked'").fetchall()
            return {
                "status": "ok", "applied": False,
                "pending": [
                    {"receipt_id": r["receipt_id"], "request_id": r["request_id"],
                     "app_id": r["app_id"], "environment": r["environment"],
                     "version": r["version"], "evidence_hash": r["evidence_hash"]}
                    for r in rows
                ],
            }
        finally:
            conn.close()
    conn = db.connect_rw(db_path)
    try:
        with db.write_tx(conn):
            rows = conn.execute("SELECT * FROM receipt WHERE state='committed_unacked'").fetchall()
            for r in rows:
                seq = db.ledger_append(
                    conn, "release.recovered", r["receipt_id"],
                    {"receipt_id": r["receipt_id"], "evidence_hash": r["evidence_hash"]}, at,
                )
                conn.execute(
                    "INSERT OR IGNORE INTO receipt_ack(receipt_id, acked_at, seq) VALUES (?,?,?)",
                    (r["receipt_id"], at, seq),
                )
                conn.execute("UPDATE receipt SET state='committed_acked' WHERE receipt_id=?",
                             (r["receipt_id"],))
            return {"status": "ok", "applied": True,
                    "recovered": [r["receipt_id"] for r in rows]}
    finally:
        conn.close()


def op_status(db_path: str, op: dict[str, Any]) -> dict[str, Any]:
    conn = db.connect_ro(db_path)
    try:
        counts = {}
        for table in ("tenant", "app", "software", "app_version", "reviewer_duty", "signature",
                      "risk", "waiver", "approval", "receipt", "release", "ledger"):
            counts[table] = conn.execute(f"SELECT COUNT(*) AS c FROM {table}").fetchone()["c"]
        return {"status": "ok", "chain": db.verify_chain(conn), "counts": counts}
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# dispatch
# ---------------------------------------------------------------------------

WRITE_OPS: dict[str, Callable[[str, dict[str, Any]], dict[str, Any]]] = {
    "publish": lambda path, op: op_publish(path, op, op.get("crash_at")),
    "approve": op_approve,
    "revoke_approval": op_revoke_approval,
    "revoke_waiver": op_revoke_waiver,
    "extend_waiver": op_extend_waiver,
    "request_waiver": op_request_waiver,
    "raise_risk": op_raise_risk,
    "transfer_reviewer": op_transfer_reviewer,
    "bump_duty": op_bump_duty,
    "register_person": op_register_person,
    "register_software": op_register_software,
    "register_risk": op_register_risk,
    "record_fix": op_record_fix,
    "recover": op_recover,
}

READ_OPS: dict[str, Callable[[str, dict[str, Any]], dict[str, Any]]] = {
    "precheck": op_precheck,
    "launch_query": op_launch_query,
    "receipt_query": op_receipt_query,
    "audit": op_audit,
    "status": op_status,
}


def dispatch(db_path: str, op: dict[str, Any]) -> dict[str, Any]:
    name = op.get("op")
    if not isinstance(name, str):
        raise GateError("E_MISSING_FIELD", "operation needs 'op'", field="op")
    if name in WRITE_OPS:
        return WRITE_OPS[name](db_path, op)
    if name in READ_OPS:
        return READ_OPS[name](db_path, op)
    raise GateError("E_UNKNOWN_OP", f"unsupported operation {name!r}", op=name)
