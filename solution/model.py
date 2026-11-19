"""Typed records and strict validation of synthetic case input.

Every loader here is defensive: unknown ids, cross-tenant references, bad
digests and malformed timestamps are rejected with a stable error code instead
of being coerced.  The gate is only as trustworthy as its input handling.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Iterable

from .errors import GateError
from .util import is_digest, is_ts, normalize_ts, parse_ts
from .versions import parse_constraint, parse_version

_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:\-]{0,63}$")
_SEVERITIES = ("low", "medium", "high", "critical")
_SEVERITY_RANK = {s: i for i, s in enumerate(_SEVERITIES)}
DEFAULT_ROLES = ("security", "engineering", "compliance")


def require_id(value: object, field_name: str) -> str:
    if not isinstance(value, str):
        raise GateError("E_BAD_TYPE", f"{field_name} must be a string", field=field_name)
    if not _ID_RE.match(value):
        raise GateError("E_BAD_FORMAT", f"{field_name} is not a valid identifier: {value!r}", field=field_name)
    return value


def require_text(value: object, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise GateError("E_BAD_TYPE", f"{field_name} must be a non-empty string", field=field_name)
    return value


def require_digest(value: object, field_name: str) -> str:
    if not is_digest(value):
        raise GateError(
            "E_BAD_FORMAT",
            f"{field_name} must look like sha256:<64 hex>",
            field=field_name,
            value=value,
        )
    return str(value)


def require_ts(value: object, field_name: str) -> str:
    if not is_ts(value):
        raise GateError("E_BAD_FORMAT", f"{field_name} must be a UTC ...Z timestamp", field=field_name)
    return normalize_ts(str(value))


def require_severity(value: object) -> str:
    if value not in _SEVERITIES:
        raise GateError("E_SEVERITY_UNKNOWN", f"severity {value!r} is not registered", value=value)
    return str(value)


def severity_rank(value: str) -> int:
    return _SEVERITY_RANK[value]


def require_list(value: object, field_name: str) -> list[Any]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise GateError("E_BAD_TYPE", f"{field_name} must be a list", field=field_name)
    return value


def require_obj(value: object, field_name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise GateError("E_BAD_TYPE", f"{field_name} must be an object", field=field_name)
    return value


# ---------------------------------------------------------------------------
# records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Tenant:
    tenant_id: str
    environments: tuple[str, ...]
    roles: tuple[str, ...] = ("security", "engineering", "compliance")


@dataclass(frozen=True)
class App:
    app_id: str
    tenant_id: str
    name: str


@dataclass(frozen=True)
class SoftwareVersion:
    tenant_id: str
    name: str
    version: str
    content_digest: str
    deps: tuple[tuple[str, dict[str, Any]], ...]
    allowed_envs: tuple[str, ...]
    published_at: str


@dataclass(frozen=True)
class AppVersion:
    app_id: str
    version: str
    tenant_id: str
    deps: tuple[tuple[str, dict[str, Any]], ...]
    lock: tuple[dict[str, str], ...] | None


@dataclass(frozen=True)
class Reviewer:
    reviewer_id: str
    tenant_id: str
    role: str
    duty_epoch: int
    duty_version: int
    active_from: str
    person_id: str


@dataclass(frozen=True)
class Signature:
    signature_id: str
    reviewer_id: str
    tenant_id: str
    status: str
    signed_at: str
    subject: str


@dataclass(frozen=True)
class Risk:
    risk_id: str
    tenant_id: str
    app_id: str
    dep_name: str
    dep_version: str
    content_digest: str
    severity: str
    status: str
    registered_at: str


@dataclass(frozen=True)
class WaiverInput:
    waiver_id: str
    risk_id: str
    tenant_id: str
    app_id: str
    content_digest: str
    environment: str
    evidence_version: str
    repair_deadline: str
    requested_by: str
    created_at: str


@dataclass(frozen=True)
class ApprovalInput:
    approval_id: str
    waiver_id: str
    reviewer_id: str
    role: str
    signature_id: str
    decision: str
    app_id: str
    app_version: str
    environment: str
    risk_id: str
    content_digest: str
    evidence_version: str
    severity_snapshot: str
    deadline_snapshot: str
    duty_epoch: int
    duty_version: int
    signed_at: str


@dataclass(frozen=True)
class FixSignalInput:
    fix_id: str
    risk_id: str
    evidence_version: str
    content_digest: str
    fixed_at: str
    verified: bool


@dataclass
class InitialState:
    tenants: list[Tenant] = field(default_factory=list)
    apps: list[App] = field(default_factory=list)
    software: list[SoftwareVersion] = field(default_factory=list)
    app_versions: list[AppVersion] = field(default_factory=list)
    reviewers: list[Reviewer] = field(default_factory=list)
    signatures: list[Signature] = field(default_factory=list)
    risks: list[Risk] = field(default_factory=list)
    waivers: list[WaiverInput] = field(default_factory=list)
    approvals: list[ApprovalInput] = field(default_factory=list)
    fix_signals: list[FixSignalInput] = field(default_factory=list)


# ---------------------------------------------------------------------------
# parsers
# ---------------------------------------------------------------------------


def parse_deps(value: object, field_name: str) -> tuple[tuple[str, dict[str, Any]], ...]:
    if value is None:
        return ()
    obj = require_obj(value, field_name)
    out: list[tuple[str, dict[str, Any]]] = []
    for name, spec in obj.items():
        if not isinstance(name, str) or not name:
            raise GateError("E_BAD_FORMAT", f"{field_name} has an empty package name")
        parse_version  # referenced for clarity; constraint validation below
        out.append((name, parse_constraint(spec)))
    out.sort(key=lambda pair: pair[0])
    return tuple(out)


def parse_lock(value: object, field_name: str) -> tuple[dict[str, str], ...] | None:
    if value is None:
        return None
    items = require_list(value, field_name)
    out = []
    for idx, item in enumerate(items):
        obj = require_obj(item, f"{field_name}[{idx}]")
        out.append(
            {
                "name": require_text(obj.get("name"), f"{field_name}[{idx}].name"),
                "version": require_text(obj.get("version"), f"{field_name}[{idx}].version"),
                "content_digest": require_digest(
                    obj.get("content_digest"), f"{field_name}[{idx}].content_digest"
                ),
            }
        )
    return tuple(out)


def parse_tenant(raw: dict[str, Any]) -> Tenant:
    envs = require_list(raw.get("environments"), "tenant.environments")
    if not envs:
        raise GateError("E_MISSING_FIELD", "tenant.environments must not be empty")
    seen = []
    for env in envs:
        e = require_id(env, "tenant.environments[]")
        if e in seen:
            raise GateError("E_DUPLICATE_ID", f"environment {e!r} declared twice")
        seen.append(e)
    roles: list[str] = []
    for role in require_list(raw.get("roles"), "tenant.roles"):
        r = require_id(role, "tenant.roles[]")
        if r in roles:
            raise GateError("E_DUPLICATE_ID", f"role {r!r} declared twice")
        roles.append(r)
    return Tenant(
        tenant_id=require_id(raw.get("tenant_id"), "tenant.tenant_id"),
        environments=tuple(seen),
        roles=tuple(roles) or DEFAULT_ROLES,
    )


def parse_app(raw: dict[str, Any]) -> App:
    return App(
        app_id=require_id(raw.get("app_id"), "app.app_id"),
        tenant_id=require_id(raw.get("tenant_id"), "app.tenant_id"),
        name=require_text(raw.get("name", raw.get("app_id")), "app.name"),
    )


def parse_software(raw: dict[str, Any]) -> SoftwareVersion:
    name = require_text(raw.get("name"), "software.name")
    version = require_text(raw.get("version"), "software.version")
    parse_version(version)
    allowed = require_list(raw.get("allowed_envs"), "software.allowed_envs")
    return SoftwareVersion(
        tenant_id=require_id(raw.get("tenant_id"), "software.tenant_id"),
        name=name,
        version=version,
        content_digest=require_digest(raw.get("content_digest"), "software.content_digest"),
        deps=parse_deps(raw.get("deps"), "software.deps"),
        allowed_envs=tuple(require_id(e, "software.allowed_envs[]") for e in allowed),
        published_at=require_ts(raw.get("published_at", "2026-01-01T00:00:00Z"), "software.published_at"),
    )


def parse_app_version(raw: dict[str, Any]) -> AppVersion:
    version = require_text(raw.get("version"), "app_version.version")
    parse_version(version)
    return AppVersion(
        app_id=require_id(raw.get("app_id"), "app_version.app_id"),
        version=version,
        tenant_id=require_id(raw.get("tenant_id"), "app_version.tenant_id"),
        deps=parse_deps(raw.get("deps"), "app_version.deps"),
        lock=parse_lock(raw.get("lock"), "app_version.lock"),
    )


def parse_reviewer(raw: dict[str, Any]) -> Reviewer:
    epoch = raw.get("duty_epoch", 1)
    duty_version = raw.get("duty_version", 1)
    for label, v in (("duty_epoch", epoch), ("duty_version", duty_version)):
        if not isinstance(v, int) or isinstance(v, bool) or v < 1:
            raise GateError("E_BAD_TYPE", f"reviewer.{label} must be a positive integer")
    return Reviewer(
        reviewer_id=require_id(raw.get("reviewer_id"), "reviewer.reviewer_id"),
        tenant_id=require_id(raw.get("tenant_id"), "reviewer.tenant_id"),
        role=require_id(raw.get("role"), "reviewer.role"),
        duty_epoch=epoch,
        duty_version=duty_version,
        active_from=require_ts(raw.get("active_from", "2026-01-01T00:00:00Z"), "reviewer.active_from"),
        person_id=require_id(raw.get("person_id", raw.get("reviewer_id")), "reviewer.person_id"),
    )


def parse_signature(raw: dict[str, Any]) -> Signature:
    return Signature(
        signature_id=require_id(raw.get("signature_id"), "signature.signature_id"),
        reviewer_id=require_id(raw.get("reviewer_id"), "signature.reviewer_id"),
        tenant_id=require_id(raw.get("tenant_id"), "signature.tenant_id"),
        status=require_text(raw.get("status"), "signature.status"),
        signed_at=require_ts(raw.get("signed_at"), "signature.signed_at"),
        subject=require_text(raw.get("subject"), "signature.subject"),
    )


def parse_risk(raw: dict[str, Any]) -> Risk:
    return Risk(
        risk_id=require_id(raw.get("risk_id"), "risk.risk_id"),
        tenant_id=require_id(raw.get("tenant_id"), "risk.tenant_id"),
        app_id=require_id(raw.get("app_id"), "risk.app_id"),
        dep_name=require_text(raw.get("dep_name"), "risk.dep_name"),
        dep_version=require_text(raw.get("dep_version"), "risk.dep_version"),
        content_digest=require_digest(raw.get("content_digest"), "risk.content_digest"),
        severity=require_severity(raw.get("severity")),
        status=require_text(raw.get("status", "open"), "risk.status"),
        registered_at=require_ts(raw.get("registered_at"), "risk.registered_at"),
    )


def parse_waiver(raw: dict[str, Any]) -> WaiverInput:
    return WaiverInput(
        waiver_id=require_id(raw.get("waiver_id"), "waiver.waiver_id"),
        risk_id=require_id(raw.get("risk_id"), "waiver.risk_id"),
        tenant_id=require_id(raw.get("tenant_id"), "waiver.tenant_id"),
        app_id=require_id(raw.get("app_id"), "waiver.app_id"),
        content_digest=require_digest(raw.get("content_digest"), "waiver.content_digest"),
        environment=require_id(raw.get("environment"), "waiver.environment"),
        evidence_version=require_text(raw.get("evidence_version"), "waiver.evidence_version"),
        repair_deadline=require_ts(raw.get("repair_deadline"), "waiver.repair_deadline"),
        requested_by=require_id(raw.get("requested_by"), "waiver.requested_by"),
        created_at=require_ts(raw.get("created_at"), "waiver.created_at"),
    )


def parse_approval(raw: dict[str, Any]) -> ApprovalInput:
    return ApprovalInput(
        approval_id=require_id(raw.get("approval_id"), "approval.approval_id"),
        waiver_id=require_id(raw.get("waiver_id"), "approval.waiver_id"),
        reviewer_id=require_id(raw.get("reviewer_id"), "approval.reviewer_id"),
        role=require_id(raw.get("role"), "approval.role"),
        signature_id=require_id(raw.get("signature_id"), "approval.signature_id"),
        decision=require_text(raw.get("decision", "grant"), "approval.decision"),
        app_id=require_id(raw.get("app_id"), "approval.app_id"),
        app_version=require_text(raw.get("app_version"), "approval.app_version"),
        environment=require_id(raw.get("environment"), "approval.environment"),
        risk_id=require_id(raw.get("risk_id"), "approval.risk_id"),
        content_digest=require_digest(raw.get("content_digest"), "approval.content_digest"),
        evidence_version=require_text(raw.get("evidence_version"), "approval.evidence_version"),
        severity_snapshot=require_severity(raw.get("severity_snapshot")),
        deadline_snapshot=require_ts(raw.get("deadline_snapshot"), "approval.deadline_snapshot"),
        duty_epoch=int(raw.get("duty_epoch", 1)),
        duty_version=int(raw.get("duty_version", 1)),
        signed_at=require_ts(raw.get("signed_at"), "approval.signed_at"),
    )


def parse_fix_signal(raw: dict[str, Any]) -> FixSignalInput:
    verified = raw.get("verified", True)
    if not isinstance(verified, bool):
        raise GateError("E_BAD_TYPE", "fix_signal.verified must be a boolean")
    return FixSignalInput(
        fix_id=require_id(raw.get("fix_id"), "fix_signal.fix_id"),
        risk_id=require_id(raw.get("risk_id"), "fix_signal.risk_id"),
        evidence_version=require_text(raw.get("evidence_version"), "fix_signal.evidence_version"),
        content_digest=require_digest(raw.get("content_digest"), "fix_signal.content_digest"),
        fixed_at=require_ts(raw.get("fixed_at"), "fix_signal.fixed_at"),
        verified=verified,
    )


def parse_initial(raw: object) -> InitialState:
    obj = require_obj(raw, "initial")
    state = InitialState()
    state.tenants = [parse_tenant(x) for x in _items(obj, "tenants", parse_obj)]
    state.apps = [parse_app(x) for x in _items(obj, "apps", parse_obj)]
    state.software = [parse_software(x) for x in _items(obj, "software", parse_obj)]
    state.app_versions = [parse_app_version(x) for x in _items(obj, "app_versions", parse_obj)]
    state.reviewers = [parse_reviewer(x) for x in _items(obj, "reviewers", parse_obj)]
    state.signatures = [parse_signature(x) for x in _items(obj, "signatures", parse_obj)]
    state.risks = [parse_risk(x) for x in _items(obj, "risks", parse_obj)]
    state.waivers = [parse_waiver(x) for x in _items(obj, "waivers", parse_obj)]
    state.approvals = [parse_approval(x) for x in _items(obj, "approvals", parse_obj)]
    state.fix_signals = [parse_fix_signal(x) for x in _items(obj, "fix_signals", parse_obj)]
    return state


def parse_obj(value: object) -> dict[str, Any]:
    return require_obj(value, "record")


def _items(obj: dict[str, Any], key: str, parser) -> Iterable[dict[str, Any]]:
    for idx, item in enumerate(require_list(obj.get(key), f"initial.{key}")):
        try:
            yield parser(item)
        except GateError as exc:
            exc.ctx.setdefault("at", f"initial.{key}[{idx}]")
            raise


def expected_signature_subject(waiver_id: str, risk_id: str, app_id: str, app_version: str, environment: str) -> str:
    """The only subject string a valid waiver signature may carry."""
    return f"waive:{waiver_id}:{risk_id}:{app_id}@{app_version}:{environment}"


def is_before(a: str, b: str) -> bool:
    return parse_ts(a) < parse_ts(b)
