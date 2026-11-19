"""Record store: bootstrap, typed loading and release evaluation over SQLite.

The store is the only module that knows SQL column layouts.  Everything above
it works with plain dicts, which keeps the policy module testable without a
database and keeps the read-only and read-write paths sharing one evaluator.
"""

from __future__ import annotations

import json
from typing import Any, Iterable

from . import db
from .errors import GateError
from .model import InitialState
from .policy import ReleaseVerdict, RiskVerdict, evaluate_risk, risk_applies, sort_risks
from .util import canonical_json, digest_of
from .versions import Catalogue, PackageVersion, closure_fingerprint, closure_rows, resolve


# ---------------------------------------------------------------------------
# bootstrap
# ---------------------------------------------------------------------------


def bootstrap(conn, state: InitialState, ts: str) -> dict[str, int]:
    """Load a fresh case into an empty database.

    Cross-record references are validated here so that every later operation can
    assume a consistent registry.
    """
    counts: dict[str, int] = {}
    tenants = {t.tenant_id: t for t in state.tenants}
    _unique([t.tenant_id for t in state.tenants], "tenant_id")

    with db.write_tx(conn):
        for t in state.tenants:
            conn.execute(
                "INSERT INTO tenant(tenant_id, environments, version_policy) VALUES (?,?,?)",
                (t.tenant_id, canonical_json(list(t.environments)), "highest_satisfying"),
            )
            for role in t.roles:
                conn.execute(
                    "INSERT INTO role_registry(tenant_id, role) VALUES (?,?)", (t.tenant_id, role)
                )
        counts["tenants"] = len(state.tenants)

        apps: dict[str, Any] = {}
        _unique([a.app_id for a in state.apps], "app_id")
        for a in state.apps:
            if a.tenant_id not in tenants:
                raise GateError("E_UNKNOWN_REF", f"app {a.app_id} references unknown tenant", app_id=a.app_id)
            apps[a.app_id] = a
            conn.execute("INSERT INTO app(app_id, tenant_id, name) VALUES (?,?,?)", (a.app_id, a.tenant_id, a.name))
        counts["apps"] = len(state.apps)

        software_pk: set[tuple[str, str, str]] = set()
        for s in state.software:
            if s.tenant_id not in tenants:
                raise GateError("E_UNKNOWN_REF", f"software {s.name} references unknown tenant")
            pk = (s.tenant_id, s.name, s.version)
            if pk in software_pk:
                raise GateError("E_DUPLICATE_ID", f"software {s.name}@{s.version} declared twice")
            software_pk.add(pk)
            conn.execute(
                "INSERT INTO software(tenant_id, name, version, content_digest, published_at,"
                " allowed_envs, superseded, revoked_at, updated_seq)"
                " VALUES (?,?,?,?,?,?,0,NULL,?)",
                (
                    s.tenant_id,
                    s.name,
                    s.version,
                    s.content_digest,
                    s.published_at,
                    canonical_json(list(s.allowed_envs)) if s.allowed_envs else None,
                    db.state_seq(conn),
                ),
            )
            conn.execute(
                "INSERT INTO software_digest_history(tenant_id, name, version, content_digest,"
                " epoch, seen_at, retired_at) VALUES (?,?,?,?,?,?,NULL)",
                (s.tenant_id, s.name, s.version, s.content_digest, db.state_seq(conn), s.published_at),
            )
            for dep_name, cons in s.deps:
                conn.execute(
                    "INSERT INTO software_dep(tenant_id, name, version, dep_name, constraint_json) VALUES (?,?,?,?,?)",
                    (s.tenant_id, s.name, s.version, dep_name, canonical_json(cons)),
                )
        counts["software"] = len(state.software)

        app_version_pk: set[tuple[str, str]] = set()
        for av in state.app_versions:
            if av.app_id not in apps:
                raise GateError("E_UNKNOWN_REF", f"app_version references unknown app {av.app_id}")
            if apps[av.app_id].tenant_id != av.tenant_id:
                raise GateError("E_TENANT_MISMATCH", f"app_version {av.app_id}@{av.version} tenant differs")
            if (av.app_id, av.version) in app_version_pk:
                raise GateError("E_DUPLICATE_ID", f"app_version {av.app_id}@{av.version} declared twice")
            app_version_pk.add((av.app_id, av.version))
            conn.execute(
                "INSERT INTO app_version(app_id, version, tenant_id, deps_json, covered, updated_seq)"
                " VALUES (?,?,?,?,NULL,?)",
                (
                    av.app_id,
                    av.version,
                    av.tenant_id,
                    canonical_json([{"name": n, "constraint": c} for n, c in av.deps]),
                    db.state_seq(conn),
                ),
            )
            if av.lock is not None:
                # The lock file is the manifest's claim about the closure.  It is
                # verified, never trusted: publishing re-resolves from scratch.
                conn.execute(
                    "UPDATE app_version SET covered=? WHERE app_id=? AND version=?",
                    (canonical_json(list(av.lock)), av.app_id, av.version),
                )
        counts["app_versions"] = len(state.app_versions)

        reviewer_ids = [r.reviewer_id for r in state.reviewers]
        _unique(reviewer_ids, "reviewer_id")
        for r in state.reviewers:
            if r.tenant_id not in tenants:
                raise GateError("E_UNKNOWN_REF", f"reviewer {r.reviewer_id} references unknown tenant")
            if r.role not in tenants[r.tenant_id].roles:
                raise GateError(
                    "E_ROLE_UNKNOWN",
                    f"reviewer post {r.role!r} is not registered for tenant {r.tenant_id}",
                    role=r.role,
                )
            held = conn.execute(
                "SELECT role FROM person_role WHERE person_id=? AND tenant_id=?",
                (r.person_id, r.tenant_id),
            ).fetchall()
            held_roles = {h["role"] for h in held} | {r.role}
            if len(held_roles) > 1:
                raise GateError(
                    "E_SEGREGATION",
                    "one person cannot hold two independent review posts",
                    person_id=r.person_id,
                    roles=sorted(held_roles),
                )
            conn.execute(
                "INSERT OR IGNORE INTO person_role(person_id, tenant_id, role) VALUES (?,?,?)",
                (r.person_id, r.tenant_id, r.role),
            )
            conn.execute(
                "INSERT INTO reviewer_duty(reviewer_id, tenant_id, person_id, role, duty_epoch,"
                " duty_version, active_from, active_to, revoked_at, updated_seq)"
                " VALUES (?,?,?,?,?,?,?,NULL,NULL,?)",
                (
                    r.reviewer_id,
                    r.tenant_id,
                    r.person_id,
                    r.role,
                    r.duty_epoch,
                    r.duty_version,
                    r.active_from,
                    db.state_seq(conn),
                ),
            )
        counts["reviewers"] = len(state.reviewers)

        sig_ids = [s.signature_id for s in state.signatures]
        _unique(sig_ids, "signature_id")
        for s in state.signatures:
            if s.reviewer_id not in set(reviewer_ids):
                raise GateError("E_UNKNOWN_REF", f"signature {s.signature_id} references unknown reviewer")
            conn.execute(
                "INSERT INTO signature(signature_id, reviewer_id, tenant_id, status, signed_at, subject)"
                " VALUES (?,?,?,?,?,?)",
                (s.signature_id, s.reviewer_id, s.tenant_id, s.status, s.signed_at, s.subject),
            )
        counts["signatures"] = len(state.signatures)

        risk_ids: set[str] = set()
        for r in state.risks:
            if r.risk_id in risk_ids:
                raise GateError("E_DUPLICATE_ID", f"risk {r.risk_id} declared twice")
            risk_ids.add(r.risk_id)
            if r.tenant_id not in tenants or r.app_id not in apps:
                raise GateError("E_UNKNOWN_REF", f"risk {r.risk_id} references unknown tenant or app")
            if apps[r.app_id].tenant_id != r.tenant_id:
                raise GateError("E_TENANT_MISMATCH", f"risk {r.risk_id} tenant differs from its app")
            conn.execute(
                "INSERT INTO risk(risk_id, tenant_id, app_id, dep_name, dep_version, content_digest,"
                " severity, status, registered_at, updated_seq) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (
                    r.risk_id,
                    r.tenant_id,
                    r.app_id,
                    r.dep_name,
                    r.dep_version,
                    r.content_digest,
                    r.severity,
                    r.status,
                    r.registered_at,
                    db.state_seq(conn),
                ),
            )
            conn.execute(
                "INSERT INTO risk_event(risk_id, seq, kind, payload) VALUES (?,?,?,?)",
                (r.risk_id, 0, "registered", canonical_json({"severity": r.severity, "status": r.status})),
            )
        counts["risks"] = len(state.risks)

        w_ids: set[str] = set()
        for w in state.waivers:
            if w.waiver_id in w_ids:
                raise GateError("E_DUPLICATE_ID", f"waiver {w.waiver_id} declared twice")
            w_ids.add(w.waiver_id)
            if w.risk_id not in risk_ids:
                raise GateError("E_UNKNOWN_REF", f"waiver {w.waiver_id} references unknown risk")
            if w.repair_deadline < w.created_at:
                raise GateError("E_TIME_ORDER", f"waiver {w.waiver_id} expires before it was created")
            risk_row = conn.execute("SELECT * FROM risk WHERE risk_id=?", (w.risk_id,)).fetchone()
            if w.content_digest != risk_row["content_digest"]:
                raise GateError(
                    "E_DIGEST_MISMATCH",
                    f"waiver {w.waiver_id} digest does not match its risk",
                    expected=risk_row["content_digest"],
                    actual=w.content_digest,
                )
            conn.execute(
                "INSERT INTO waiver(waiver_id, risk_id, tenant_id, app_id, content_digest, environment,"
                " evidence_version, repair_deadline, requested_by, status, created_at, updated_seq)"
                " VALUES (?,?,?,?,?,?,?,?,?,'active',?,?)",
                (
                    w.waiver_id,
                    w.risk_id,
                    risk_row["tenant_id"],
                    risk_row["app_id"],
                    w.content_digest,
                    w.environment,
                    w.evidence_version,
                    w.repair_deadline,
                    w.requested_by,
                    w.created_at,
                    db.state_seq(conn),
                ),
            )
            conn.execute(
                "INSERT INTO waiver_event(waiver_id, seq, kind, payload) VALUES (?,?,?,?)",
                (w.waiver_id, 0, "created", canonical_json({"deadline": w.repair_deadline})),
            )
        counts["waivers"] = len(state.waivers)

        approval_ids: set[str] = set()
        for a in state.approvals:
            if a.approval_id in approval_ids:
                raise GateError("E_DUPLICATE_ID", f"approval {a.approval_id} declared twice")
            approval_ids.add(a.approval_id)
            if a.waiver_id not in w_ids:
                raise GateError("E_UNKNOWN_REF", f"approval {a.approval_id} references unknown waiver")
            if a.reviewer_id not in set(reviewer_ids):
                raise GateError("E_UNKNOWN_REF", f"approval {a.approval_id} references unknown reviewer")
            if a.signature_id not in set(sig_ids):
                raise GateError("E_UNKNOWN_REF", f"approval {a.approval_id} references unknown signature")
            if a.decision not in {"grant", "deny"}:
                raise GateError("E_BAD_FORMAT", f"approval decision {a.decision!r} is not grant/deny")
            conn.execute(
                "INSERT INTO approval(approval_id, waiver_id, reviewer_id, role, signature_id, decision,"
                " app_id, app_version, environment, risk_id, content_digest, evidence_version,"
                " severity_snapshot, deadline_snapshot, duty_epoch, duty_version, signed_at, status,"
                " revoked_reason, seq) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'active',NULL,?)",
                (
                    a.approval_id,
                    a.waiver_id,
                    a.reviewer_id,
                    a.role,
                    a.signature_id,
                    a.decision,
                    a.app_id,
                    a.app_version,
                    a.environment,
                    a.risk_id,
                    a.content_digest,
                    a.evidence_version,
                    a.severity_snapshot,
                    a.deadline_snapshot,
                    a.duty_epoch,
                    a.duty_version,
                    a.signed_at,
                    db.state_seq(conn),
                ),
            )
            conn.execute(
                "INSERT INTO approval_event(approval_id, seq, kind, payload) VALUES (?,?,?,?)",
                (a.approval_id, 0, "registered", canonical_json({"reviewer": a.reviewer_id})),
            )
        counts["approvals"] = len(state.approvals)

        fix_ids: set[str] = set()
        for f in state.fix_signals:
            if f.fix_id in fix_ids:
                raise GateError("E_DUPLICATE_ID", f"fix signal {f.fix_id} declared twice")
            fix_ids.add(f.fix_id)
            if f.risk_id not in risk_ids:
                raise GateError("E_UNKNOWN_REF", f"fix signal {f.fix_id} references unknown risk")
            conn.execute(
                "INSERT INTO fix_signal(fix_id, risk_id, evidence_version, content_digest, fixed_at,"
                " verified, seq) VALUES (?,?,?,?,?,?,?)",
                (
                    f.fix_id,
                    f.risk_id,
                    f.evidence_version,
                    f.content_digest,
                    f.fixed_at,
                    1 if f.verified else 0,
                    db.state_seq(conn),
                ),
            )
            if f.verified and f.evidence_version:
                conn.execute("UPDATE risk SET status='fixed', updated_seq=? WHERE risk_id=?", (db.state_seq(conn), f.risk_id))
        counts["fix_signals"] = len(state.fix_signals)

        db.ledger_append(conn, "bootstrap", "state", {"counts": counts}, ts)
    return counts


def _unique(values: Iterable[str], label: str) -> None:
    seen: set[str] = set()
    for v in values:
        if v in seen:
            raise GateError("E_DUPLICATE_ID", f"duplicate {label}: {v}", value=v)
        seen.add(v)


# ---------------------------------------------------------------------------
# loading
# ---------------------------------------------------------------------------


def _row(r) -> dict[str, Any]:
    return dict(r)


def load_app(conn, app_id: str) -> dict[str, Any]:
    row = conn.execute("SELECT * FROM app WHERE app_id=?", (app_id,)).fetchone()
    if row is None:
        raise GateError("E_UNKNOWN_REF", f"unknown app {app_id!r}", app_id=app_id)
    return _row(row)


def load_tenant(conn, tenant_id: str) -> dict[str, Any]:
    row = conn.execute("SELECT * FROM tenant WHERE tenant_id=?", (tenant_id,)).fetchone()
    if row is None:
        raise GateError("E_UNKNOWN_REF", f"unknown tenant {tenant_id!r}", tenant_id=tenant_id)
    return _row(row)


def load_app_version(conn, app_id: str, version: str) -> dict[str, Any]:
    row = conn.execute("SELECT * FROM app_version WHERE app_id=? AND version=?", (app_id, version)).fetchone()
    if row is None:
        raise GateError("E_VERSION_UNKNOWN", f"release {app_id}@{version} is not declared", app_id=app_id, version=version)
    return _row(row)


def load_catalogue(conn, tenant_id: str) -> Catalogue:
    cat = Catalogue()
    rows = conn.execute("SELECT * FROM software WHERE tenant_id=?", (tenant_id,)).fetchall()
    deps = conn.execute("SELECT * FROM software_dep WHERE tenant_id=?", (tenant_id,)).fetchall()
    dep_map: dict[tuple[str, str], list[tuple[str, str]]] = {}
    for d in deps:
        dep_map.setdefault((d["name"], d["version"]), []).append((d["dep_name"], d["constraint_json"]))
    for r in rows:
        spec = dep_map.get((r["name"], r["version"]), [])
        cat.add(
            PackageVersion(
                name=r["name"],
                version=r["version"],
                content_digest=r["content_digest"],
                deps=tuple(sorted((n, _constraint_text(json.loads(c))) for n, c in spec)),
                allowed_envs=tuple(json.loads(r["allowed_envs"])) if r["allowed_envs"] else (),
                superseded=bool(r["superseded"]),
                revoked=r["revoked_at"] is not None,
            )
        )
    return cat


def _constraint_text(cons: dict[str, Any]) -> str:
    from .versions import constraint_text

    return constraint_text(cons)


def app_roots(app_version: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    deps = json.loads(app_version["deps_json"])
    roots = []
    for item in deps:
        roots.append((item["name"], item["constraint"]))
    return roots


def resolve_for(conn, app_version: dict[str, Any], environment: str) -> dict[str, PackageVersion]:
    cat = load_catalogue(conn, app_version["tenant_id"])
    return resolve(cat, app_roots(app_version), environment)


def load_risks(conn, tenant_id: str, app_id: str) -> list[dict[str, Any]]:
    rows = conn.execute(
        "SELECT * FROM risk WHERE tenant_id=? AND app_id=? ORDER BY risk_id", (tenant_id, app_id)
    ).fetchall()
    return [_row(r) for r in rows]


def load_risk(conn, risk_id: str) -> dict[str, Any] | None:
    row = conn.execute("SELECT * FROM risk WHERE risk_id=?", (risk_id,)).fetchone()
    return _row(row) if row else None


def load_waivers_for_risk(conn, risk_id: str) -> list[dict[str, Any]]:
    rows = conn.execute(
        "SELECT * FROM waiver WHERE risk_id=? ORDER BY created_at DESC, waiver_id DESC", (risk_id,)
    ).fetchall()
    return [_row(r) for r in rows]


def load_waiver(conn, waiver_id: str) -> dict[str, Any] | None:
    row = conn.execute("SELECT * FROM waiver WHERE waiver_id=?", (waiver_id,)).fetchone()
    return _row(row) if row else None


def load_approvals(conn, waiver_id: str) -> list[dict[str, Any]]:
    rows = conn.execute(
        "SELECT * FROM approval WHERE waiver_id=? ORDER BY signed_at, approval_id", (waiver_id,)
    ).fetchall()
    return [_row(r) for r in rows]


def load_reviewers(conn, tenant_id: str) -> dict[str, dict[str, Any]]:
    rows = conn.execute("SELECT * FROM reviewer_duty WHERE tenant_id=?", (tenant_id,)).fetchall()
    return {r["reviewer_id"]: _row(r) for r in rows}


def load_person_roles(conn, tenant_id: str) -> dict[str, set[str]]:
    rows = conn.execute("SELECT person_id, role FROM person_role WHERE tenant_id=?", (tenant_id,)).fetchall()
    out: dict[str, set[str]] = {}
    for r in rows:
        out.setdefault(r["person_id"], set()).add(r["role"])
    return out


def load_signatures(conn) -> dict[str, dict[str, Any]]:
    rows = conn.execute("SELECT * FROM signature").fetchall()
    return {r["signature_id"]: _row(r) for r in rows}


def latest_active_waiver(conn, risk_id: str, environment: str, app_id: str) -> dict[str, Any] | None:
    rows = load_waivers_for_risk(conn, risk_id)
    for w in rows:
        if w["status"] != "active":
            continue
        if w["environment"] != environment or w["app_id"] != app_id:
            continue
        return w
    return None


# ---------------------------------------------------------------------------
# evaluation
# ---------------------------------------------------------------------------


def evaluate_release(
    conn,
    *,
    tenant_id: str,
    app_id: str,
    version: str,
    environment: str,
    at: str,
    resolved: dict[str, PackageVersion] | None = None,
) -> ReleaseVerdict:
    """Evaluate one release candidate against the full closure and registry."""
    app = load_app(conn, app_id)
    if app["tenant_id"] != tenant_id:
        raise GateError("E_TENANT_MISMATCH", "app does not belong to the tenant", app_id=app_id)
    tenant = load_tenant(conn, tenant_id)
    if environment not in json.loads(tenant["environments"]):
        raise GateError("E_ENV_UNKNOWN", f"environment {environment!r} is not declared", environment=environment)

    av = load_app_version(conn, app_id, version)
    if av["tenant_id"] != tenant_id:
        raise GateError("E_TENANT_MISMATCH", "release candidate tenant differs")

    pins = resolved if resolved is not None else resolve_for(conn, av, environment)
    closure = {row["name"]: row for row in closure_rows(pins)}

    reviewers = load_reviewers(conn, tenant_id)
    signatures = load_signatures(conn)
    verdict = ReleaseVerdict(
        tenant_id=tenant_id,
        app_id=app_id,
        version=version,
        environment=environment,
        at=at,
        closure=closure_rows(pins),
        closure_fingerprint=closure_fingerprint(pins),
    )

    for risk in sort_risks(load_risks(conn, tenant_id, app_id)):
        if not risk_applies(risk, closure):
            continue
        if risk["status"] == "fixed":
            verdict.risks.append(
                RiskVerdict(
                    risk_id=risk["risk_id"],
                    dep_name=risk["dep_name"],
                    dep_version=risk["dep_version"],
                    severity=risk["severity"],
                    disposition="fixed",
                    detail="verified fix signal present",
                )
            )
            continue
        waiver = latest_active_waiver(conn, risk["risk_id"], environment, app_id)
        approvals = load_approvals(conn, waiver["waiver_id"]) if waiver else []
        rv = evaluate_risk(
            risk,
            waiver,
            approvals,
            reviewers,
            signatures,
            tenant_id=tenant_id,
            app_id=app_id,
            app_version=version,
            environment=environment,
            at=at,
        )
        verdict.risks.append(rv)
        if rv.disposition == "blocked":
            verdict.blocked.append(
                {
                    "risk_id": risk["risk_id"],
                    "package": f"{risk['dep_name']}@{risk['dep_version']}",
                    "severity": risk["severity"],
                    "code": rv.code,
                    "detail": rv.detail,
                }
            )

    verdict.blocked.sort(key=lambda b: (b["code"], b["risk_id"]))
    return verdict


def manifest_coverage(app_version: dict[str, Any], pins: dict[str, PackageVersion]) -> dict[str, Any]:
    """Compare the declared lock to the resolved closure."""
    return compare_declared_closure(app_version, pins)


def compare_declared_closure(app_version: dict[str, Any], pins: dict[str, PackageVersion]) -> dict[str, Any]:
    """Check the optional declared lock against the real resolved closure.

    A missing lock is not an error - the gate still resolves from the app's
    dependency constraints and enforces the real closure.  A declared lock that
    disagrees is a hard failure: the manifest claims to be complete and is not.
    """
    from .versions import compare_closure

    raw = app_version["covered"]
    if raw is None:
        return {"declared": False, "diffs": [], "complete": True}
    declared = json.loads(raw)
    diffs = compare_closure(pins, declared)
    return {"declared": True, "diffs": diffs, "complete": not diffs}


def evidence_payload(verdict: ReleaseVerdict) -> dict[str, Any]:
    return {
        "tenant_id": verdict.tenant_id,
        "app_id": verdict.app_id,
        "version": verdict.version,
        "environment": verdict.environment,
        "at": verdict.at,
        "closure_fingerprint": verdict.closure_fingerprint,
        "closure": verdict.closure,
        "risks": [r.as_dict() for r in verdict.risks],
        "basis": verdict.basis(),
    }


def evidence_hash(payload: dict[str, Any]) -> str:
    return digest_of(payload)
