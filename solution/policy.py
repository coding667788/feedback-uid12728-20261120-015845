"""Release policy: which risks block, which waivers and approvals are live.

The functions here are pure: they take already-loaded rows and return a
structured verdict.  That makes the same logic usable by the read-only
precheck, by the writer inside its transaction, and by the read-only launch
query, with no risk of the three drifting apart.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

from .errors import GateError
from .model import expected_signature_subject, severity_rank
from .util import canonical_json, digest_of

# Signature status values understood by the simulator.  Only "valid" authorises
# anything; the rest are recorded and reported verbatim.
SIGNATURE_VALID = "valid"
SEVERITY_DENY_WAIVER = "critical"


@dataclass
class RiskVerdict:
    risk_id: str
    dep_name: str
    dep_version: str
    severity: str
    disposition: str  # "fixed" | "waived" | "blocked"
    code: str = ""
    detail: str = ""
    waiver_id: str = ""
    evidence_version: str = ""
    approvals_used: list[str] = field(default_factory=list)
    reviewers_used: list[str] = field(default_factory=list)
    roles_used: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "risk_id": self.risk_id,
            "package": f"{self.dep_name}@{self.dep_version}",
            "severity": self.severity,
            "disposition": self.disposition,
            "code": self.code,
            "detail": self.detail,
            "waiver_id": self.waiver_id,
            "approvals": list(self.approvals_used),
            "reviewers": list(self.reviewers_used),
            "roles": list(self.roles_used),
        }


@dataclass
class ReleaseVerdict:
    tenant_id: str
    app_id: str
    version: str
    environment: str
    at: str
    closure: list[dict[str, str]]
    closure_fingerprint: str
    risks: list[RiskVerdict] = field(default_factory=list)
    blocked: list[dict[str, str]] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def authorized(self) -> bool:
        return not self.blocked

    def basis(self) -> str:
        """Digest of every fact the authorisation rests on.

        A precheck token carries this value.  Publishing recomputes it inside
        the write transaction; any material drift in the closure, the risks,
        the waivers, the approvals or the signer duties changes it and the
        token is rejected as stale.
        """
        return digest_of(
            {
                "tenant": self.tenant_id,
                "app": self.app_id,
                "version": self.version,
                "environment": self.environment,
                "closure": self.closure,
                "risks": [
                    {
                        "risk_id": r.risk_id,
                        "severity": r.severity,
                        "disposition": r.disposition,
                        "code": r.code,
                        "waiver_id": r.waiver_id,
                        "approvals": r.approvals_used,
                        "reviewers": r.reviewers_used,
                        "roles": r.roles_used,
                    }
                    for r in self.risks
                ],
            }
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "authorized": self.authorized,
            "tenant_id": self.tenant_id,
            "app_id": self.app_id,
            "version": self.version,
            "environment": self.environment,
            "at": self.at,
            "closure_fingerprint": self.closure_fingerprint,
            "closure": self.closure,
            "risks": [r.as_dict() for r in self.risks],
            "blocked": list(self.blocked),
            "basis": self.basis(),
        }


def _blocked(verdict: RiskVerdict) -> bool:
    return verdict.disposition == "blocked"


def evaluate_risk(
    risk: dict[str, Any],
    waiver: dict[str, Any] | None,
    approvals: Iterable[dict[str, Any]],
    reviewers: dict[str, dict[str, Any]],
    signatures: dict[str, dict[str, Any]],
    *,
    tenant_id: str,
    app_id: str,
    app_version: str,
    environment: str,
    at: str,
) -> RiskVerdict:
    """Decide whether one applicable risk blocks this release."""
    rv = RiskVerdict(
        risk_id=risk["risk_id"],
        dep_name=risk["dep_name"],
        dep_version=risk["dep_version"],
        severity=risk["severity"],
        disposition="blocked",
    )
    if risk["severity"] == SEVERITY_DENY_WAIVER:
        rv.code = "E_APPROVAL_SEVERITY"
        rv.detail = "critical severity cannot be waived or approved away"
        return rv

    if waiver is None:
        rv.code = "E_RISK_OPEN"
        rv.detail = f"risk {risk['risk_id']} is unfixed and has no waiver"
        return rv

    rv.waiver_id = waiver["waiver_id"]
    rv.evidence_version = waiver["evidence_version"]

    if waiver["status"] != "active":
        rv.code = "E_WAIVER_REVOKED"
        rv.detail = f"waiver {waiver['waiver_id']} is {waiver['status']}"
        return rv
    if waiver["tenant_id"] != tenant_id or waiver["app_id"] != app_id:
        rv.code = "E_APP_TENANT_MISMATCH"
        rv.detail = "waiver is bound to another tenant or application"
        return rv
    if waiver["risk_id"] != risk["risk_id"]:
        rv.code = "E_WAIVER_RISK_MISMATCH"
        rv.detail = "waiver is bound to a different risk"
        return rv
    if waiver["environment"] != environment:
        rv.code = "E_WAIVER_ENV"
        rv.detail = f"waiver targets {waiver['environment']}, release targets {environment}"
        return rv
    if waiver["content_digest"] != risk["content_digest"]:
        rv.code = "E_DIGEST_MISMATCH"
        rv.detail = "waiver content digest does not match the risk digest"
        return rv
    # The deadline is exclusive: repair must land strictly before it.
    if at >= waiver["repair_deadline"]:
        rv.code = "E_WAIVER_EXPIRED"
        rv.detail = f"repair deadline {waiver['repair_deadline']} has been reached at {at}"
        return rv
    if waiver["evidence_version"] != risk["dep_version"]:
        rv.code = "E_WAIVER_EVIDENCE"
        rv.detail = "waiver evidence version does not match the released dependency"
        return rv

    candidates: list[tuple[dict[str, Any], dict[str, Any], dict[str, Any]]] = []
    seen_person_roles: dict[str, set[str]] = {}
    for ap in approvals:
        if ap["status"] != "active" or ap["decision"] != "grant":
            continue
        reviewer = reviewers.get(ap["reviewer_id"])
        signature = signatures.get(ap["signature_id"])
        stale_code, stale_detail = _approval_staleness(
            ap,
            waiver,
            risk,
            reviewer,
            signature,
            tenant_id=tenant_id,
            app_id=app_id,
            app_version=app_version,
            environment=environment,
            at=at,
        )
        if stale_code:
            continue
        person = reviewer["person_id"]
        seen_person_roles.setdefault(person, set()).add(ap["role"])
        candidates.append((ap, reviewer, signature))

    # One person filling two required posts is a segregation failure, not a
    # shortcut: refuse rather than silently counting them twice.
    for person, roles in sorted(seen_person_roles.items()):
        if len(roles) > 1:
            rv.code = "E_SEGREGATION"
            rv.detail = f"person {person} signed under posts {sorted(roles)}"
            return rv

    # Keep one live signature per (person, role), most recent first.
    by_person: dict[str, tuple[dict[str, Any], dict[str, Any], dict[str, Any]]] = {}
    for item in sorted(candidates, key=lambda t: (t[0]["signed_at"], t[0]["approval_id"]), reverse=True):
        by_person.setdefault(item[1]["person_id"], item)
    valid = sorted(by_person.values(), key=lambda t: (t[0]["role"], t[0]["reviewer_id"]))

    if len(valid) < 2:
        rv.code = "E_APPROVAL_MISSING"
        rv.detail = f"need two approvals from distinct posts, found {len(valid)}"
        return rv
    if len({t[0]["role"] for t in valid}) < 2:
        rv.code = "E_APPROVAL_ROLE_CONFLICT"
        rv.detail = "both approvals came from the same post"
        return rv

    chosen = valid[:2]
    rv.disposition = "waived"
    rv.approvals_used = [t[0]["approval_id"] for t in chosen]
    rv.reviewers_used = [t[1]["person_id"] for t in chosen]
    rv.roles_used = [t[0]["role"] for t in chosen]
    return rv


def _approval_staleness(
    ap: dict[str, Any],
    waiver: dict[str, Any],
    risk: dict[str, Any],
    reviewer: dict[str, Any] | None,
    signature: dict[str, Any] | None,
    *,
    tenant_id: str,
    app_id: str,
    app_version: str,
    environment: str,
    at: str,
) -> tuple[str, str]:
    """Return ``(code, detail)`` when an approval is stale, else ``("", "")``."""
    if ap["waiver_id"] != waiver["waiver_id"]:
        return "E_APPROVAL_STALE", "approval targets a different waiver"
    if ap["app_id"] != app_id or ap["app_version"] != app_version:
        return "E_APPROVAL_STALE", "approval targets a different application version"
    if ap["environment"] != environment:
        return "E_APPROVAL_STALE", "approval targets a different environment"
    if ap["risk_id"] != risk["risk_id"]:
        return "E_WAIVER_RISK_MISMATCH", "approval targets a different risk"
    if ap["content_digest"] != risk["content_digest"] or ap["content_digest"] != waiver["content_digest"]:
        return "E_DIGEST_MISMATCH", "approval content digest does not match"
    if ap["evidence_version"] != waiver["evidence_version"]:
        return "E_WAIVER_EVIDENCE", "approval evidence version differs from the waiver"
    if ap["severity_snapshot"] != risk["severity"]:
        return "E_RISK_SEVERITY_RAISED", "severity changed after this approval was signed"
    if ap["deadline_snapshot"] != waiver["repair_deadline"]:
        return "E_APPROVAL_STALE", "repair deadline was extended or shortened after approval"
    if reviewer is None:
        return "E_APPROVAL_DUTY_UNKNOWN", "approver holds no duty record"
    if reviewer["revoked_at"] is not None:
        return "E_APPROVAL_DUTY_REVOKED", "approval duty was revoked"
    if reviewer["active_from"] > at:
        return "E_APPROVAL_DUTY_REVOKED", "approver was not yet on duty at release time"
    if reviewer["role"] != ap["role"]:
        return "E_APPROVAL_STALE", "approver changed post after signing"
    if int(reviewer["duty_epoch"]) != int(ap["duty_epoch"]) or int(reviewer["duty_version"]) != int(
        ap["duty_version"]
    ):
        return "E_APPROVAL_DUTY_STALE", "duty epoch or version changed after signing"
    if signature is None:
        return "E_APPROVAL_SIGNATURE", "signature record is missing"
    if signature["reviewer_id"] != ap["reviewer_id"] or signature["tenant_id"] != tenant_id:
        return "E_APPROVAL_SIGNATURE", "signature was not issued to this reviewer"
    if signature["status"] != SIGNATURE_VALID:
        return "E_APPROVAL_SIGNATURE", f"signature status is {signature['status']!r}"
    if signature["signed_at"] > at:
        return "E_APPROVAL_SIGNATURE", "signature is dated after the release"
    expected = expected_signature_subject(
        waiver["waiver_id"], risk["risk_id"], app_id, app_version, environment
    )
    if signature["subject"] != expected:
        return "E_APPROVAL_SIGNATURE", "signature subject does not cover this exact waiver and release"
    return "", ""


def waiver_fingerprint(waiver: dict[str, Any]) -> str:
    return digest_of(
        {
            "waiver_id": waiver["waiver_id"],
            "risk_id": waiver["risk_id"],
            "tenant_id": waiver["tenant_id"],
            "app_id": waiver["app_id"],
            "content_digest": waiver["content_digest"],
            "environment": waiver["environment"],
            "evidence_version": waiver["evidence_version"],
            "repair_deadline": waiver["repair_deadline"],
        }
    )


def approval_fingerprint(ap: dict[str, Any]) -> str:
    return digest_of(
        {
            k: ap[k]
            for k in (
                "approval_id",
                "waiver_id",
                "reviewer_id",
                "role",
                "signature_id",
                "decision",
                "app_id",
                "app_version",
                "environment",
                "risk_id",
                "content_digest",
                "evidence_version",
                "severity_snapshot",
                "deadline_snapshot",
                "duty_epoch",
                "duty_version",
                "signed_at",
            )
        }
    )


def risk_applies(risk: dict[str, Any], closure: dict[str, dict[str, str]]) -> bool:
    """A risk applies only when its exact package identity is in the closure.

    Name, version *and* content digest must match.  Upgrading the dependency,
    or replacing its content, retires the risk - which is the whole point of
    binding findings to a content digest.
    """
    entry = closure.get(risk["dep_name"])
    if entry is None:
        return False
    if entry["version"] != risk["dep_version"]:
        return False
    return entry["content_digest"] == risk["content_digest"]


def sort_risks(risks: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(
        risks,
        key=lambda r: (-severity_rank(r["severity"]), r["dep_name"], r["risk_id"]),
    )


def canonical_basis_payload(verdict: ReleaseVerdict) -> str:
    return canonical_json(
        {
            "tenant": verdict.tenant_id,
            "app": verdict.app_id,
            "version": verdict.version,
            "environment": verdict.environment,
            "closure": verdict.closure,
            "risks": [
                {
                    "risk_id": r.risk_id,
                    "severity": r.severity,
                    "disposition": r.disposition,
                    "waiver_id": r.waiver_id,
                    "approvals": r.approvals_used,
                }
                for r in verdict.risks
            ],
        }
    )


def ensure_no_blockers(verdict: ReleaseVerdict) -> None:
    if verdict.blocked:
        first = verdict.blocked[0]
        raise GateError(
            first["code"],
            first["detail"],
            risk_id=first.get("risk_id", ""),
            blocked=[dict(b) for b in verdict.blocked],
        )
