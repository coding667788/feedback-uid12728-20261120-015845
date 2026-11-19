"""Stable error codes shared by the CLI, engine and tests.

Every code is a short upper snake case token.  Codes are part of the public
contract documented in ``README.md``; tests assert on them directly.
"""

from __future__ import annotations

ERROR_CODES: dict[str, str] = {
    # --- input shape -------------------------------------------------------
    "E_INPUT": "input document is not a JSON object or is unreadable",
    "E_INPUT_VERSION": "unsupported case document schema_version",
    "E_UNKNOWN_OP": "operation name is not supported",
    "E_MISSING_FIELD": "a required field is absent",
    "E_BAD_TYPE": "a field has the wrong JSON type",
    "E_BAD_FORMAT": "a field is well typed but malformed (id, digest, time)",
    "E_DUPLICATE_ID": "an identifier is declared more than once",
    "E_UNKNOWN_REF": "a reference points at a record that does not exist",
    # --- registries --------------------------------------------------------
    "E_TENANT_MISMATCH": "a record is used across tenant boundaries",
    "E_APP_MISMATCH": "a record belongs to a different application",
    "E_APP_TENANT_MISMATCH": "a record is bound to a different tenant or application",
    "E_DIGEST_MISMATCH": "content digest does not match the bound value",
    "E_DIGEST_REVERTED": "a candidate reverted to a previously seen content digest",
    "E_SEVERITY_UNKNOWN": "severity is not one of low/medium/high/critical",
    "E_ROLE_UNKNOWN": "reviewer role is not registered for the tenant",
    "E_TIME_ORDER": "an expiry precedes its creation time",
    # --- dependency closure ------------------------------------------------
    "E_DEP_MISSING": "a dependency name is not declared by the tenant",
    "E_DEP_NO_VERSION": "no version of a dependency satisfies the constraint",
    "E_DEP_AMBIGUOUS": "a dependency constraint resolves to several candidates",
    "E_DEP_CYCLE": "dependency graph contains a cycle",
    "E_DEP_ENV_MISMATCH": "dependency is not allowed in the target environment",
    "E_DEP_CONFLICT": "two reachability paths demand incompatible dependency versions",
    "E_MANIFEST_INCOMPLETE": "manifest omits part of the dependency closure",
    # --- risk and waiver ---------------------------------------------------
    "E_RISK_OPEN": "an unfixed risk blocks the release",
    "E_RISK_UNKNOWN": "risk reference is unknown",
    "E_RISK_SEVERITY_RAISED": "risk severity was raised above the approved level",
    "E_WAIVER_REQUIRED": "no waiver covers the risk for this release",
    "E_WAIVER_EXPIRED": "the waiver repair deadline has passed",
    "E_WAIVER_ENV": "waiver does not target the release environment",
    "E_WAIVER_EVIDENCE": "waiver evidence version does not match the release",
    "E_WAIVER_RISK_MISMATCH": "waiver is bound to a different risk",
    "E_WAIVER_REVOKED": "waiver was revoked",
    # --- approvals ---------------------------------------------------------
    "E_APPROVAL_MISSING": "fewer than the required approvals are registered",
    "E_APPROVAL_STALE": "approval no longer matches the release or risk",
    "E_APPROVAL_ROLE_CONFLICT": "two required approvals share one role",
    "E_APPROVAL_SELF": "a reviewer approved their own submission",
    "E_APPROVAL_DUTY_REVOKED": "approval duty was revoked before the release",
    "E_APPROVAL_SEVERITY": "critical severity cannot be waived or approved away",
    "E_APPROVAL_SIGNATURE": "simulated signature status is not valid",
    "E_APPROVAL_DUPLICATE": "the same reviewer signed twice for one requirement",
    "E_APPROVAL_DUTY_UNKNOWN": "reviewer holds no approval duty record",
    "E_APPROVAL_DUTY_STALE": "approval duty record changed after the signature",
    "E_SEGREGATION": "one person cannot satisfy both required posts",
    # --- precheck / publish ------------------------------------------------
    "E_PRECHECK_REQUIRED": "publish requires a precheck token for the release",
    "E_PRECHECK_UNKNOWN": "precheck token was never issued",
    "E_PRECHECK_CONSUMED": "precheck token was already used",
    "E_PRECHECK_STALE": "resolved state changed after the precheck",
    "E_VERSION_UNKNOWN": "release version is not declared",
    "E_POINTER_UNCHANGED": "release already points at this version",
    "E_ENV_UNKNOWN": "environment is not declared for the tenant",
    "E_LOCK_TIMEOUT": "another writer held the ledger lock past the deadline",
    "E_COMMIT_UNSIGNED_GUARD": "publish committed but receipt was not acknowledged",
    "E_IDEMPOTENCY_CONFLICT": "replayed request id maps to different content",
    # --- read views --------------------------------------------------------
    "E_STORE_BUSY": "read-only store could not be opened",
    "E_BARRIER_TIMEOUT": "a cross-process rendezvous point was never reached",
    "E_WORKER_DIED": "a worker process exited before returning a result",
}


class GateError(Exception):
    """An expected, user facing rejection.

    ``code`` is the stable token from :data:`ERROR_CODES`; ``detail`` is a
    human readable explanation; ``ctx`` carries machine inspectable extras such
    as the offending record id so callers can assert on it.
    """

    def __init__(self, code: str, detail: str = "", **ctx: object) -> None:
        if code not in ERROR_CODES:
            raise AssertionError(f"undeclared error code: {code}")
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail
        self.ctx = ctx

    def as_dict(self) -> dict[str, object]:
        out: dict[str, object] = {"code": self.code, "detail": self.detail or ERROR_CODES[self.code]}
        if self.ctx:
            out["context"] = dict(self.ctx)
        return out
